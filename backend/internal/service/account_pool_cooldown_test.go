package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/stretchr/testify/require"
)

func TestAccountPoolCooldownExpiryIsolationAndStatus(t *testing.T) {
	var cache accountPoolCooldown
	now := time.Unix(1700000000, 0)
	group := int64(1)
	otherGroup := int64(2)
	key := poolCooldownKey(&group, "model-a", PlatformOpenAI)
	cache.mark(key, http.StatusTooManyRequests, now)
	var cooldown *AccountPoolCooldownError
	require.ErrorAs(t, cache.check(key, now.Add(time.Second)), &cooldown)
	require.Equal(t, http.StatusTooManyRequests, cooldown.StatusCode)
	require.Equal(t, 4*time.Second, cooldown.RetryAfter)
	require.ErrorIs(t, cooldown, ErrNoAvailableAccounts)
	for _, isolated := range []accountPoolCooldownKey{
		poolCooldownKey(&otherGroup, "model-a", PlatformOpenAI),
		poolCooldownKey(&group, "model-b", PlatformOpenAI),
		poolCooldownKey(&group, "model-a", PlatformAnthropic),
		poolCooldownKey(nil, "model-a", PlatformOpenAI),
	} {
		require.NoError(t, cache.check(isolated, now))
	}
	cache.mark(key, http.StatusServiceUnavailable, now.Add(4*time.Second))
	require.NoError(t, cache.check(key, now.Add(accountPoolCooldownDuration)), "rejections must not slide expiry")
	cache.mark(key, http.StatusServiceUnavailable, now.Add(accountPoolCooldownDuration))
	require.ErrorAs(t, cache.check(key, now.Add(accountPoolCooldownDuration)), &cooldown)
	require.Equal(t, http.StatusServiceUnavailable, cooldown.StatusCode)
	cache.mark(key, http.StatusTooManyRequests, now.Add(6*time.Second))
	require.ErrorAs(t, cache.check(key, now.Add(7*time.Second)), &cooldown)
	require.Equal(t, http.StatusTooManyRequests, cooldown.StatusCode)
	require.Equal(t, 3*time.Second, cooldown.RetryAfter, "503 to 429 upgrade must not renew the deadline")
}

func TestAccountPoolCooldownBoundedAndDoesNotCacheUnrelatedFailures(t *testing.T) {
	var cache accountPoolCooldown
	now := time.Unix(1700000000, 0)
	for i := range accountPoolCooldownCapacity + 5 {
		cache.mark(poolCooldownKey(nil, fmt.Sprint(i), PlatformOpenAI), http.StatusServiceUnavailable, now.Add(time.Duration(i)))
	}
	require.Len(t, cache.entries, accountPoolCooldownCapacity)
	key := poolCooldownKey(nil, "no-cache", PlatformOpenAI)
	for _, selectionErr := range []error{
		errors.New("database unavailable"),
		fmt.Errorf("%w supporting model: missing", ErrNoAvailableAccounts),
		ErrNoAvailableCompactAccounts,
	} {
		original := selectionErr
		cache.finishSelection(key, nil, &selectionErr)
		require.Same(t, original, selectionErr)
		require.NoError(t, cache.check(key, time.Now()))
	}
	selectionErr := error(emptyAccountPoolError{})
	cache.finishSelection(key, map[int64]struct{}{1: {}}, &selectionErr)
	require.NoError(t, cache.check(key, time.Now()), "request-local exclusions cannot poison the shared pool")
	largeKey := poolCooldownKey(nil, strings.Repeat("x", 513), PlatformOpenAI)
	cache.finishSelection(largeKey, nil, &selectionErr)
	require.Error(t, selectionErr, "cache bypass must never turn selection failure into success")
}

type emptyPoolCountingRepository struct {
	AccountRepository
	calls int
}

func (r *emptyPoolCountingRepository) ListSchedulableUngroupedByPlatform(context.Context, string) ([]Account, error) {
	r.calls++
	return nil, nil
}

func TestAccountPoolCooldownEmptySelectionsSkipRepositoryAndUpstream(t *testing.T) {
	ctx := context.Background()
	t.Run("OpenAI legacy and scheduler", func(t *testing.T) {
		repo := &emptyPoolCountingRepository{}
		s := &OpenAIGatewayService{accountRepo: repo, cfg: &config.Config{}}
		account, err := s.SelectAccountForModelWithExclusions(ctx, nil, "", "model-a", nil)
		require.Nil(t, account)
		var cooldown *AccountPoolCooldownError
		require.ErrorAs(t, err, &cooldown)
		require.Equal(t, 1, repo.calls)
		account, err = s.SelectAccountForModelWithExclusions(ctx, nil, "", "model-a", nil)
		require.Nil(t, account)
		require.ErrorAs(t, err, &cooldown)
		selection, _, err := s.SelectAccountWithScheduler(ctx, nil, "", "", "model-a", nil, OpenAIUpstreamTransportAny, false)
		require.Nil(t, selection)
		require.ErrorAs(t, err, &cooldown)
		require.Equal(t, 1, repo.calls, "cooldown must return before selection, token refresh or upstream forwarding")
		key := poolCooldownKey(nil, "model-a", PlatformOpenAI)
		s.poolCooldown.entries[key] = accountPoolCooldownEntry{until: time.Now().Add(-time.Second), status: 503}
		account, err = s.SelectAccountForModelWithExclusions(ctx, nil, "", "model-a", nil)
		require.Nil(t, account)
		require.ErrorAs(t, err, &cooldown)
		require.Equal(t, 2, repo.calls, "expiry must resume eligibility discovery")
	})
	t.Run("Gateway forced platform", func(t *testing.T) {
		repo := &emptyPoolCountingRepository{}
		s := &GatewayService{accountRepo: repo, cfg: &config.Config{}}
		forced := context.WithValue(ctx, ctxkey.ForcePlatform, PlatformAntigravity)
		account, err := s.SelectAccountForModelWithExclusions(forced, nil, "", "model-a", nil)
		require.Nil(t, account)
		var cooldown *AccountPoolCooldownError
		require.ErrorAs(t, err, &cooldown)
		require.Equal(t, 1, repo.calls)
		selection, err := s.SelectAccountWithLoadAwareness(forced, nil, "", "model-a", nil, "", 0)
		require.Nil(t, selection)
		require.ErrorAs(t, err, &cooldown)
		require.Equal(t, 1, repo.calls)
	})
}

func TestAccountPoolCooldownExhausted503StopsActualSchedulers(t *testing.T) {
	// No repositories or HTTP clients are installed: entering selection or
	// forwarding rather than the cooldown gate would panic this fixture.
	openAI := &OpenAIGatewayService{}
	openAI.MarkAccountPoolCooldown(nil, "model-a", PlatformOpenAI, http.StatusServiceUnavailable)
	selection, _, err := openAI.SelectAccountWithScheduler(context.Background(), nil, "", "", "model-a", nil, OpenAIUpstreamTransportAny, false)
	require.Nil(t, selection)
	var cooldown *AccountPoolCooldownError
	require.ErrorAs(t, err, &cooldown)
	require.Equal(t, http.StatusServiceUnavailable, cooldown.StatusCode)
	gateway := &GatewayService{}
	gateway.MarkAccountPoolCooldown(nil, "model-a", PlatformAnthropic, http.StatusServiceUnavailable)
	selected, err := gateway.SelectAccountForModelWithExclusions(context.Background(), nil, "", "model-a", nil)
	require.Nil(t, selected)
	require.ErrorAs(t, err, &cooldown)
}

func TestAccountPoolCooldownRequiresWholePoolFailures(t *testing.T) {
	ctx := context.Background()
	groupID := int64(71234)
	accounts := []Account{
		{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive, Schedulable: true, GroupIDs: []int64{groupID}, Extra: map[string]any{"openai_compact_supported": true}},
		{ID: 2, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive, Schedulable: true, GroupIDs: []int64{groupID}, Extra: map[string]any{"openai_compact_supported": false}},
	}
	s := &OpenAIGatewayService{accountRepo: schedulerTestOpenAIAccountRepo{accounts: accounts}, cfg: &config.Config{}}
	failed := map[int64]struct{}{1: {}}
	selected, err := s.selectAccountForModelWithExclusions(ctx, &groupID, PlatformOpenAI, "", "model-a", failed, true, 0, "", false)
	require.Nil(t, selected)
	require.ErrorIs(t, err, ErrNoAvailableCompactAccounts)
	s.MarkAccountPoolCooldownIfExhausted(ctx, &groupID, "model-a", PlatformOpenAI, failed, http.StatusServiceUnavailable)
	require.NoError(t, s.CheckAccountPoolCooldown(&groupID, "model-a", PlatformOpenAI))
	selected, err = s.SelectAccountForModelWithExclusions(ctx, &groupID, "", "model-a", failed)
	require.NoError(t, err, "compact failure must not block a healthy ordinary request")
	require.Equal(t, int64(2), selected.ID)
	failed[2] = struct{}{}
	s.MarkAccountPoolCooldownIfExhausted(ctx, &groupID, "model-a", PlatformOpenAI, failed, http.StatusServiceUnavailable)
	selected, err = s.SelectAccountForModelWithExclusions(ctx, &groupID, "", "model-a", nil)
	require.Nil(t, selected)
	var cooldown *AccountPoolCooldownError
	require.ErrorAs(t, err, &cooldown)
	require.Equal(t, http.StatusServiceUnavailable, cooldown.StatusCode)
	require.Positive(t, cooldown.RetryAfter)
	require.LessOrEqual(t, cooldown.RetryAfter, 5*time.Second)
}
