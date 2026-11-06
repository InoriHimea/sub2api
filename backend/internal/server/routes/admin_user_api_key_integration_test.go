//go:build unit

package routes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	_ "github.com/Wei-Shaw/sub2api/ent/runtime"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/handler/admin"
	"github.com/Wei-Shaw/sub2api/internal/pkg/adminaccess"
	"github.com/Wei-Shaw/sub2api/internal/pkg/timezone"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// This test never starts containers, discovers runtime configuration or calls a
// model. The caller must supply a dedicated, disposable database and Redis.
func TestAdminCreateUserAPIKeyIntegration(t *testing.T) {
	dsn, address := os.Getenv("SUB2API_ADMIN_KEY_TEST_DSN"), os.Getenv("SUB2API_ADMIN_KEY_TEST_REDIS_ADDR")
	if dsn == "" && address == "" {
		t.Skip("explicit owned PostgreSQL/Redis fixtures are required")
	}
	require.Equal(t, "1", os.Getenv("SUB2API_ADMIN_KEY_TEST_OWNED"), "acknowledge ownership before writing test fixtures")
	databaseURL, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, databaseURL.Scheme)
	require.True(t, strings.HasSuffix(databaseURL.Path, "_test"))
	hostAllowed := func(host string) bool {
		return host == "127.0.0.1" || host == "localhost" || host == "::1"
	}
	require.True(t, hostAllowed(databaseURL.Hostname()), "only an explicit local/owned test host is allowed")
	redisHost, _, err := net.SplitHostPort(address)
	require.NoError(t, err)
	require.True(t, hostAllowed(redisHost), "only an explicit local/owned Redis fixture is allowed")
	require.NoError(t, timezone.Init("UTC"))
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(12)
	require.NoError(t, db.PingContext(ctx))
	var databaseName string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT current_database()").Scan(&databaseName))
	require.Equal(t, strings.TrimPrefix(databaseURL.Path, "/"), databaseName)
	require.NoError(t, repository.ApplyMigrations(ctx, db))
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	rdb := redis.NewClient(&redis.Options{Addr: address, DB: 0})
	t.Cleanup(func() { _ = rdb.Close() })
	require.NoError(t, rdb.Ping(ctx).Err())

	cfg := &config.Config{
		JWT: config.JWTConfig{Secret: "integration-fixture-not-a-runtime-secret", ExpireHour: 1},
		APIKeyAuth: config.APIKeyAuthCacheConfig{
			L1Size: 128, L1TTLSeconds: 600, L2TTLSeconds: 600, NegativeTTLSeconds: 600, Singleflight: true,
		},
	}
	users := repository.NewUserRepository(client, db)
	groups := repository.NewGroupRepository(client, db)
	subscriptions := repository.NewUserSubscriptionRepository(client)
	keys := repository.NewAPIKeyRepository(client, db)
	cache := repository.NewAPIKeyCache(rdb)
	service.SetDefaultIdempotencyCoordinator(service.NewIdempotencyCoordinator(
		repository.NewIdempotencyRepository(client, db), service.DefaultIdempotencyConfig()))
	t.Cleanup(func() { service.SetDefaultIdempotencyCoordinator(nil) })
	keyService := service.NewAPIKeyService(keys, users, groups, subscriptions, nil, cache, cfg)
	peer := service.NewAPIKeyService(keys, users, groups, subscriptions, nil, cache, cfg)
	peer.StartAuthCacheInvalidationSubscriber(ctx)
	t.Cleanup(peer.StopAuthCacheInvalidationSubscriber)
	require.Eventually(t, func() bool { return peer.AuthCacheInvalidationSubscriberHealth().Connected }, 5*time.Second, 10*time.Millisecond)
	settingsRepo := repository.NewSettingRepository(client)
	const adminCredential = "admin-integration-fixture-not-a-runtime-secret"
	require.NoError(t, settingsRepo.Set(ctx, service.SettingKeyAdminAPIKey, adminCredential))
	require.NoError(t, settingsRepo.Set(ctx, service.SettingKeyBackendModeEnabled, "true"))
	settings := service.NewSettingService(settingsRepo, cfg)
	settings.SetScopedAdminKeyRepository(repository.NewScopedAdminKeyRepository(db))
	adminService := service.NewAdminService(cfg, users, repository.NewAdminGroupRepository(client, db),
		nil, nil, keys, nil, nil, nil, nil, nil, nil, keyService, client, settings,
		nil, subscriptions, nil, nil, nil, nil, nil, nil)
	auth := service.NewAuthService(nil, nil, nil, nil, cfg, nil, nil, nil, nil, nil, nil, nil, nil)
	userService := service.NewUserService(users, nil, nil, nil)
	audits := service.NewAuditLogService(repository.NewAuditLogRepository(db), nil)
	audits.Start()
	var stopAudit sync.Once
	t.Cleanup(func() { stopAudit.Do(audits.Stop) })
	gin.SetMode(gin.TestMode)
	routerFor := func(creator *service.APIKeyService) *httptest.Server {
		router := gin.New()
		group := router.Group("/api/v1/admin")
		group.Use(gin.HandlerFunc(middleware.NewAdminAuthMiddleware(auth, userService, settings, nil)))
		group.Use(gin.HandlerFunc(middleware.NewAuditLogMiddleware(audits)))
		registerUserManagementRoutes(group, &handler.Handlers{Admin: &handler.AdminHandlers{
			User: &admin.UserHandler{}, UserAttribute: &admin.UserAttributeHandler{},
			APIKey: admin.NewAdminAPIKeyHandler(adminService, creator),
		}})
		server := httptest.NewServer(router)
		t.Cleanup(server.Close)
		return server
	}
	router := routerFor(keyService)
	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	createUser := func(label, role string) *service.User {
		user := &service.User{Email: label + "-" + nonce + "@test.invalid", PasswordHash: "fixture-only-not-used-for-login",
			Role: role, Status: service.StatusActive, Concurrency: 10, RestrictPublicGroups: true}
		require.NoError(t, users.Create(ctx, user))
		return user
	}
	actor := createUser("admin", service.RoleAdmin)
	owner := createUser("owner", service.RoleUser)
	other := createUser("other", service.RoleUser)
	createGroup := func(label string, userID int64) *service.Group {
		group := &service.Group{Name: label + "-" + nonce, Platform: service.PlatformAnthropic, Status: service.StatusActive,
			IsExclusive: true, SubscriptionType: "subscription", RateMultiplier: 1, DefaultValidityDays: 30,
			ImageRateMultiplier: 1, BatchImageDiscountMultiplier: 1, BatchImageHoldMultiplier: 1}
		require.NoError(t, groups.Create(ctx, group))
		require.NoError(t, subscriptions.Create(ctx, &service.UserSubscription{UserID: userID, GroupID: group.ID,
			StartsAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour), Status: service.StatusActive}))
		return group
	}
	ownerGroup, otherGroup := createGroup("owner", owner.ID), createGroup("other", other.ID)
	request := func(server *httptest.Server, userID int64, key string, payload map[string]any, header, credential string) *httptest.ResponseRecorder {
		body, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			panic(marshalErr)
		}
		req, requestErr := http.NewRequest(http.MethodPost, server.URL+fmt.Sprintf("/api/v1/admin/users/%d/api-keys", userID), bytes.NewReader(body))
		if requestErr != nil {
			panic(requestErr)
		}
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", nonce+"-"+key)
		}
		if header != "" {
			req.Header.Set(header, credential)
		}
		rec := httptest.NewRecorder()
		resp, requestErr := server.Client().Do(req)
		if requestErr != nil {
			panic(requestErr)
		}
		defer resp.Body.Close()
		rec.Code = resp.StatusCode
		for key, values := range resp.Header {
			rec.Header()[key] = values
		}
		if _, requestErr = io.Copy(rec.Body, resp.Body); requestErr != nil {
			panic(requestErr)
		}
		return rec
	}
	countKeys := func(userID int64, name string) int {
		var count int
		require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM api_keys WHERE user_id=$1 AND name=$2", userID, name).Scan(&count))
		return count
	}
	var originalResponse []byte
	canary := "sk-admin-integration-canary-" + nonce
	t.Run("persistence_negative_cache_and_replay", func(t *testing.T) {
		for _, svc := range []*service.APIKeyService{keyService, peer} {
			_, lookupErr := svc.GetByKey(ctx, canary)
			require.ErrorIs(t, lookupErr, service.ErrAPIKeyNotFound)
			require.Eventually(t, func() bool {
				before := svc.AuthLookupMetrics().Total
				_, lookupErr := svc.GetByKey(ctx, canary)
				return errors.Is(lookupErr, service.ErrAPIKeyNotFound) && svc.AuthLookupMetrics().Total == before
			}, 3*time.Second, 10*time.Millisecond, "prove a negative L1 hit before creation")
		}
		sum := sha256.Sum256([]byte(canary))
		hash := hex.EncodeToString(sum[:])
		// Also exercise invalidation of a retained legacy Redis negative entry.
		require.NoError(t, cache.SetAuthCache(ctx, hash, &service.APIKeyAuthCacheEntry{NotFound: true}, time.Minute))
		payload := map[string]any{"name": "owner-key-" + nonce, "group_id": ownerGroup.ID, "custom_key": canary, "user_id": actor.ID}
		rec := request(router, owner.ID, "owner", payload, "x-api-key", adminCredential)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		originalResponse = append([]byte(nil), rec.Body.Bytes()...)
		cached, cacheErr := rdb.Exists(ctx, "apikey:auth:"+hash).Result()
		require.NoError(t, cacheErr)
		require.EqualValues(t, 0, cached)
		stored, readErr := keys.GetByKey(ctx, canary)
		require.NoError(t, readErr)
		require.Equal(t, owner.ID, stored.UserID)
		require.Equal(t, ownerGroup.ID, *stored.GroupID)
		validated, user, authErr := keyService.ValidateKey(ctx, canary)
		require.NoError(t, authErr)
		require.Equal(t, stored.ID, validated.ID)
		require.Equal(t, owner.ID, user.ID)
		positive, cacheErr := cache.GetAuthCache(ctx, hash)
		require.NoError(t, cacheErr)
		require.False(t, positive.NotFound)
		require.NotNil(t, positive.Snapshot)
		require.Equal(t, owner.ID, positive.Snapshot.UserID)
		require.Eventually(t, func() bool {
			key, lookupErr := peer.GetByKey(ctx, canary)
			return lookupErr == nil && key.UserID == owner.ID
		}, 3*time.Second, 10*time.Millisecond, "Redis pub/sub must clear the peer's negative L1 without waiting 600 seconds")
		replay := request(router, owner.ID, "owner", payload, "x-api-key", adminCredential)
		require.Equal(t, http.StatusOK, replay.Code)
		require.JSONEq(t, string(originalResponse), replay.Body.String())
		require.Equal(t, 1, countKeys(owner.ID, "owner-key-"+nonce))
		conflict := request(router, other.ID, "owner", payload, "x-api-key", adminCredential)
		require.Equal(t, http.StatusConflict, conflict.Code)
	})
	t.Run("authentication_and_target_subscription", func(t *testing.T) {
		userToken, tokenErr := auth.GenerateToken(ctx, other)
		require.NoError(t, tokenErr)
		for _, tc := range []struct {
			name, header, credential string
			target, group            int64
			status                   int
		}{
			{"anonymous", "", "", owner.ID, ownerGroup.ID, http.StatusUnauthorized},
			{"ordinary-user", "Authorization", "Bearer " + userToken, owner.ID, ownerGroup.ID, http.StatusForbidden},
			{"wrong-admin-key", "x-api-key", "invalid-fixture", owner.ID, ownerGroup.ID, http.StatusUnauthorized},
			{"other-user-subscription", "x-api-key", adminCredential, other.ID, ownerGroup.ID, http.StatusForbidden},
		} {
			rec := request(router, tc.target, tc.name, map[string]any{"name": tc.name + nonce, "group_id": tc.group}, tc.header, tc.credential)
			require.Equal(t, tc.status, rec.Code, tc.name)
			require.Equal(t, 0, countKeys(tc.target, tc.name+nonce))
		}
		adminToken, tokenErr := auth.GenerateToken(ctx, actor)
		require.NoError(t, tokenErr)
		created := request(router, owner.ID, "admin-jwt", map[string]any{
			"name": "admin-jwt-" + nonce, "group_id": ownerGroup.ID,
		}, "Authorization", "Bearer "+adminToken)
		require.Equal(t, http.StatusOK, created.Code)
		require.Equal(t, 1, countKeys(owner.ID, "admin-jwt-"+nonce))
		require.True(t, settings.IsBackendModeEnabled(ctx))
	})
	t.Run("restricted_admin_permissions_and_actor_isolation", func(t *testing.T) {
		createCredential := func(permission string) string {
			key, _, err := settings.CreateScopedAdminKey(ctx, service.ScopedAdminKeyInput{
				Name: "synthetic-" + permission, Enabled: true,
				Policy: adminaccess.Policy{GlobalPermissions: []string{permission}},
			}, actor.ID)
			require.NoError(t, err)
			return key
		}
		readKey := createCredential("users.read")
		createKey := createCredential("users.api_keys.create")
		secondKey := createCredential("users.api_keys.create")
		payload := map[string]any{"name": "scoped-" + nonce, "group_id": ownerGroup.ID}
		require.Equal(t, http.StatusForbidden, request(router, owner.ID, "scoped", payload, "x-api-key", readKey).Code)
		for _, credential := range []string{createKey, secondKey} {
			created := request(router, owner.ID, "scoped", payload, "x-api-key", credential)
			require.Equal(t, http.StatusOK, created.Code)
			replay := request(router, owner.ID, "scoped", payload, "x-api-key", credential)
			require.Equal(t, "true", replay.Header().Get("X-Idempotency-Replayed"))
			require.JSONEq(t, created.Body.String(), replay.Body.String())
		}
		require.Equal(t, 2, countKeys(owner.ID, "scoped-"+nonce), "separate admin credentials must not share a replay")
	})
	t.Run("invalid_creation_and_unavailable_coordinator", func(t *testing.T) {
		payload := map[string]any{"name": "missing-idempotency-" + nonce}
		require.Equal(t, http.StatusBadRequest, request(router, owner.ID, "", payload, "x-api-key", adminCredential).Code)
		require.Zero(t, countKeys(owner.ID, "missing-idempotency-"+nonce))
		inactive := createUser("inactive", service.RoleUser)
		_, updateErr := db.ExecContext(ctx, "UPDATE users SET status='inactive' WHERE id=$1", inactive.ID)
		require.NoError(t, updateErr)
		require.Equal(t, http.StatusForbidden, request(router, inactive.ID, "inactive", payload, "x-api-key", adminCredential).Code)
		require.Zero(t, countKeys(inactive.ID, "missing-idempotency-"+nonce))
		for i, payload := range []map[string]any{
			{"name": "   "}, {"name": "negative", "quota": -1},
			{"name": "expiry", "expires_in_days": 0},
			{"name": "bad-ip", "ip_whitelist": []string{"not-an-ip"}},
		} {
			rec := request(router, owner.ID, fmt.Sprintf("invalid-%d", i), payload, "x-api-key", adminCredential)
			require.Equal(t, http.StatusBadRequest, rec.Code)
		}
		coordinator := service.DefaultIdempotencyCoordinator()
		service.SetDefaultIdempotencyCoordinator(nil)
		defer service.SetDefaultIdempotencyCoordinator(coordinator)
		rec := request(router, owner.ID, "unavailable", map[string]any{"name": "unavailable-" + nonce}, "x-api-key", adminCredential)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Zero(t, countKeys(owner.ID, "unavailable-"+nonce))
	})
	t.Run("concurrent_idempotency_persists_one_key", func(t *testing.T) {
		payload := map[string]any{"name": "concurrent-" + nonce, "group_id": otherGroup.ID}
		recorders := make([]*httptest.ResponseRecorder, 8)
		var wg sync.WaitGroup
		for i := range recorders {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				recorders[i] = request(router, other.ID, "concurrent", payload, "x-api-key", adminCredential)
			}(i)
		}
		wg.Wait()
		successes := 0
		for _, rec := range recorders {
			require.Contains(t, []int{http.StatusOK, http.StatusConflict}, rec.Code)
			if rec.Code == http.StatusOK {
				successes++
			}
		}
		require.Positive(t, successes)
		require.Equal(t, 1, countKeys(other.ID, "concurrent-"+nonce))
		replay := request(router, other.ID, "concurrent", payload, "x-api-key", adminCredential)
		require.Equal(t, http.StatusOK, replay.Code)
		require.Equal(t, 1, countKeys(other.ID, "concurrent-"+nonce))
	})
	t.Run("database_write_failure_is_not_success", func(t *testing.T) {
		readOnlyURL := *databaseURL
		query := readOnlyURL.Query()
		query.Set("default_transaction_read_only", "on")
		readOnlyURL.RawQuery = query.Encode()
		readOnlyDB, openErr := sql.Open("postgres", readOnlyURL.String())
		require.NoError(t, openErr)
		defer readOnlyDB.Close()
		var readOnly string
		require.NoError(t, readOnlyDB.QueryRowContext(ctx, "SHOW default_transaction_read_only").Scan(&readOnly))
		require.Equal(t, "on", readOnly)
		readOnlyClient := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, readOnlyDB)))
		readOnlyKeys := repository.NewAPIKeyRepository(readOnlyClient, readOnlyDB)
		readOnlyCreator := service.NewAPIKeyService(readOnlyKeys, users, groups, subscriptions, nil, cache, cfg)
		rec := request(routerFor(readOnlyCreator), owner.ID, "db-failure", map[string]any{
			"name": "db-failure-" + nonce, "group_id": ownerGroup.ID,
		}, "x-api-key", adminCredential)
		require.Equal(t, http.StatusInternalServerError, rec.Code)
		require.Equal(t, 0, countKeys(owner.ID, "db-failure-"+nonce))
	})
	stopAudit.Do(audits.Stop)
	rows, err := db.QueryContext(ctx, "SELECT request_body, extra::text FROM audit_logs WHERE action=$1 AND path LIKE $2",
		"admin.users.api_keys.create", "/api/v1/admin/users/%/api-keys")
	require.NoError(t, err)
	defer rows.Close()
	count := 0
	for rows.Next() {
		var body, extra string
		require.NoError(t, rows.Scan(&body, &extra))
		require.Equal(t, "<credential-bearing body omitted>", body)
		require.NotContains(t, body+extra, canary)
		require.NotContains(t, extra, "custom_key")
		require.NotContains(t, extra, "owner-key-")
		count++
	}
	require.NoError(t, rows.Err())
	require.Positive(t, count, "assert actual PostgreSQL audit persistence, not only a mock")
}
