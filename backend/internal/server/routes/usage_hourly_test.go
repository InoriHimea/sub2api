//go:build unit

package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/handler/admin"
	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

type hourlyUsers struct{ service.UserRepository }

func (r *hourlyUsers) GetByID(_ context.Context, id int64) (*service.User, error) {
	role := service.RoleAdmin
	if id == 2 {
		role = service.RoleUser
	}
	return &service.User{ID: id, Role: role, Status: service.StatusActive, Concurrency: 1, TokenVersion: 1}, nil
}

func (r *hourlyUsers) GetUserAvatar(context.Context, int64) (*service.UserAvatar, error) {
	return nil, nil
}

type hourlyFailureRepo struct{ service.UsageLogRepository }

func (r *hourlyFailureRepo) GetHourlyUsage(context.Context, usagestats.HourlyUsageFilter) ([]usagestats.HourlyUsageRow, error) {
	return nil, errors.New("private DSN and SQL must not escape")
}

func hourlyServer(t *testing.T, repo service.UsageLogRepository) (*httptest.Server, string, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "hourly-synthetic-test-secret", ExpireHour: 1}}
	auth := service.NewAuthService(nil, nil, nil, nil, cfg, nil, nil, nil, nil, nil, nil, nil, nil)
	users := service.NewUserService(&hourlyUsers{}, nil, nil, nil)
	adminToken, err := auth.GenerateToken(context.Background(), &service.User{ID: 1, Role: service.RoleAdmin, TokenVersion: 1})
	require.NoError(t, err)
	userToken, err := auth.GenerateToken(context.Background(), &service.User{ID: 2, Role: service.RoleUser, TokenVersion: 1})
	require.NoError(t, err)
	usage := service.NewUsageService(repo, nil, nil, nil)
	h := &handler.Handlers{Admin: &handler.AdminHandlers{Usage: admin.NewUsageHandler(usage, nil, nil, nil)}}
	router := gin.New()
	group := router.Group("/api/v1/admin", gin.HandlerFunc(middleware.NewAdminAuthMiddleware(auth, users, nil, nil)))
	registerUsageRoutes(group, h)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server, adminToken, userToken
}
func hourlyGET(t *testing.T, server *httptest.Server, token, query string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/admin/usage/hourly?"+query, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}
func hourlyQuery(start, end string, extra ...string) string {
	q := url.Values{"start_time": {start}, "end_time": {end}}
	for i := 0; i < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	return q.Encode()
}
func TestUsageHourlyAuthorizationAndInvalidRanges(t *testing.T) {
	server, adminToken, userToken := hourlyServer(t, &hourlyFailureRepo{})
	valid := hourlyQuery("2026-11-04T08:00:00+08:00", "2026-11-04T09:00:00+08:00")
	status, _ := hourlyGET(t, server, "", valid)
	require.Equal(t, http.StatusUnauthorized, status)
	status, _ = hourlyGET(t, server, userToken, valid)
	require.Equal(t, http.StatusForbidden, status)
	for _, query := range []string{
		"", hourlyQuery("2026-11-04", "2026-11-05"),
		hourlyQuery("2026-11-04T00:00:00Z", "2026-11-04T00:00:00Z"),
		hourlyQuery("2026-11-05T00:00:00Z", "2026-11-04T00:00:00Z"),
		hourlyQuery("2026-11-01T00:00:00Z", "2026-12-02T00:00:01Z"),
		hourlyQuery("2026-11-04T00:00:00Z", "2026-11-05T00:00:00Z", "group_id", "-1"),
		hourlyQuery("2026-11-04T00:00:00Z", "2026-11-05T00:00:00Z", "group_id", "0"),
		hourlyQuery("2026-11-04T00:00:00Z", "2026-11-05T00:00:00Z", "group_id", "oops"),
	} {
		status, _ = hourlyGET(t, server, adminToken, query)
		require.Equal(t, http.StatusBadRequest, status, query)
	}
	status, body := hourlyGET(t, server, adminToken, valid)
	require.Equal(t, http.StatusInternalServerError, status)
	require.NotContains(t, string(body), "private DSN")
}
func TestUsageHourlyPostgresHTTPIntegration(t *testing.T) {
	dsn := os.Getenv("SUB2API_USAGE_HOURLY_TEST_DSN")
	if dsn == "" || os.Getenv("SUB2API_USAGE_HOURLY_TEST_OWNED") != "1" {
		t.Skip("explicit owned loopback PostgreSQL fixture required")
	}
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, parsed.Scheme)
	require.Contains(t, []string{"127.0.0.1", "localhost", "::1"}, parsed.Hostname())
	require.True(t, strings.HasSuffix(parsed.Path, "_test"), "refusing non-test database")
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = db.ExecContext(ctx, `CREATE TEMP TABLE usage_logs (
 created_at timestamptz NOT NULL,group_id bigint,model text NOT NULL,requested_model text,
 input_tokens bigint NOT NULL DEFAULT 1,output_tokens bigint NOT NULL DEFAULT 2,
 cache_creation_tokens bigint NOT NULL DEFAULT 3,cache_read_tokens bigint NOT NULL DEFAULT 4,
 total_cost numeric NOT NULL DEFAULT 2,actual_cost numeric NOT NULL DEFAULT 6,
 account_stats_cost numeric,account_rate_multiplier numeric,duration_ms bigint);
 INSERT INTO usage_logs(created_at,group_id,model,requested_model,total_cost,account_stats_cost,account_rate_multiplier,duration_ms) VALUES
 ('2026-11-04T00:29:59Z',5,'stored','requested-a',2,NULL,2,900),
 ('2026-11-04T00:30:00Z',5,'stored',' requested-a ',2,NULL,2,100),
 ('2026-11-04T00:45:00Z',5,'other-stored','requested-a',2,3,2,NULL),
 ('2026-11-04T00:50:00Z',5,'stored','requested-a',1,NULL,NULL,0),
 ('2026-11-04T01:15:00Z',5,'stored','requested-b',2,NULL,1,300),
 ('2026-11-04T01:20:00Z',6,'stored','requested-a',2,NULL,1,50),
 ('2026-11-04T01:25:00Z',NULL,'fallback','',2,NULL,1,NULL),
 ('2026-11-04T02:00:00Z',5,'stored','requested-a',2,NULL,1,200),
 ('2026-11-04T02:30:00Z',5,'stored','requested-a',2,NULL,1,999);
 SET TIME ZONE 'America/New_York'; SET default_transaction_read_only=on;`)
	require.NoError(t, err)
	repo := repository.NewUsageLogRepository(nil, db)
	server, token, _ := hourlyServer(t, repo)
	query := hourlyQuery("2026-11-04T08:30:00+08:00", "2026-11-04T10:30:00+08:00")
	status, body := hourlyGET(t, server, token, query)
	require.Equal(t, 200, status, string(body))
	var response struct {
		Code int `json:"code"`
		Data struct {
			StartTime   time.Time                   `json:"start_time"`
			EndTime     time.Time                   `json:"end_time"`
			Granularity string                      `json:"granularity"`
			Rows        []usagestats.HourlyUsageRow `json:"rows"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &response))
	require.Zero(t, response.Code)
	require.Equal(t, "hour", response.Data.Granularity)
	require.Equal(t, "2026-11-04T00:30:00Z", response.Data.StartTime.Format(time.RFC3339))
	require.Len(t, response.Data.Rows, 5)
	row := response.Data.Rows[0]
	require.EqualValues(t, 5, *row.GroupID)
	require.Equal(t, "requested-a", row.Model)
	require.EqualValues(t, 3, row.Requests)
	require.EqualValues(t, 30, row.TotalTokens)
	require.EqualValues(t, 100, row.DurationSumMs)
	require.EqualValues(t, 2, row.DurationCount)
	require.Equal(t, 5.0, row.Cost)
	require.Equal(t, 18.0, row.ActualCost)
	require.Equal(t, 11.0, row.AccountCost)
	require.Equal(t, "2026-11-04T00:00:00Z", row.BucketStart.Format(time.RFC3339))
	require.Equal(t, "2026-11-04T01:00:00Z", row.BucketEnd.Format(time.RFC3339))
	nullRow := response.Data.Rows[1]
	require.Nil(t, nullRow.GroupID)
	require.Equal(t, "fallback", nullRow.Model)
	require.Zero(t, nullRow.DurationSumMs)
	require.Zero(t, nullRow.DurationCount)
	status, body = hourlyGET(t, server, token, query+"&group_id=5&model=requested-a")
	require.Equal(t, 200, status)
	require.NoError(t, json.Unmarshal(body, &response))
	require.Len(t, response.Data.Rows, 2)
	var sum, count, requests int64
	for _, r := range response.Data.Rows {
		sum += r.DurationSumMs
		count += r.DurationCount
		requests += r.Requests
	}
	require.EqualValues(t, 300, sum)
	require.EqualValues(t, 3, count)
	require.EqualValues(t, 4, requests)
	status, body = hourlyGET(t, server, token, hourlyQuery("2026-11-04T00:29:59.9999999Z", "2026-11-04T00:30:00.0000004Z"))
	require.Equal(t, 200, status)
	require.NoError(t, json.Unmarshal(body, &response))
	require.Len(t, response.Data.Rows, 1)
	require.EqualValues(t, 1, response.Data.Rows[0].Requests)
	status, body = hourlyGET(t, server, token, hourlyQuery("2026-11-05T00:00:00Z", "2026-11-05T06:00:00Z"))
	require.Equal(t, 200, status)
	require.Contains(t, string(body), `"rows":[]`)
	// Bound overflow is an explicit failure, never a truncated successful dataset.
	_, err = db.Exec(`SET default_transaction_read_only=off; INSERT INTO usage_logs(created_at,group_id,model) SELECT '2026-11-04T03:00:00Z',5,'limit-'||i FROM generate_series(1,100001) i;SET default_transaction_read_only=on;`)
	require.NoError(t, err)
	status, body = hourlyGET(t, server, token, hourlyQuery("2026-11-04T03:00:00Z", "2026-11-04T04:00:00Z"))
	require.Equal(t, http.StatusUnprocessableEntity, status)
	require.NotContains(t, string(body), `"rows"`)
	t.Log("actual loopback HTTP -> admin auth -> handler -> service -> repository -> read-only PostgreSQL: boundaries, UTC, null/zero durations, costs, sparse/filtered results and explicit overflow passed")
}
