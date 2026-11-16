package service

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
)

const (
	accountPoolCooldownDuration = 5 * time.Second
	accountPoolCooldownCapacity = 4096
)

var errEmptyAccountPool = errors.New("empty schedulable account pool")

type emptyAccountPoolError struct{}

func (emptyAccountPoolError) Error() string        { return ErrNoAvailableAccounts.Error() }
func (emptyAccountPoolError) Unwrap() error        { return ErrNoAvailableAccounts }
func (emptyAccountPoolError) Is(target error) bool { return target == errEmptyAccountPool }

// AccountPoolCooldownError describes local pool unavailability, not an upstream
// response. Only status and expiry are cached; account credentials and response
// bodies must never be retained by the negative cache.
type AccountPoolCooldownError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *AccountPoolCooldownError) Error() string { return "account pool temporarily unavailable" }
func (e *AccountPoolCooldownError) Unwrap() error { return ErrNoAvailableAccounts }

type accountPoolCooldownKey struct {
	groupID  int64
	hasGroup bool
	model    string
	platform string
}

type accountPoolCooldownEntry struct {
	until  time.Time
	status int
}

type accountPoolCooldown struct {
	mu      sync.Mutex
	entries map[accountPoolCooldownKey]accountPoolCooldownEntry
}

func poolCooldownKey(groupID *int64, model, platform string) accountPoolCooldownKey {
	key := accountPoolCooldownKey{model: model, platform: platform}
	if groupID != nil {
		key.groupID, key.hasGroup = *groupID, true
	}
	return key
}

func (c *accountPoolCooldown) check(key accountPoolCooldownKey, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}
	if !now.Before(entry.until) {
		delete(c.entries, key)
		return nil
	}
	return &AccountPoolCooldownError{StatusCode: entry.status, RetryAfter: entry.until.Sub(now)}
}

func (c *accountPoolCooldown) mark(key accountPoolCooldownKey, status int, now time.Time) {
	if status != http.StatusServiceUnavailable && status != http.StatusTooManyRequests {
		return
	}
	if len(key.model) > 512 || len(key.platform) > 64 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[accountPoolCooldownKey]accountPoolCooldownEntry)
	}
	// Repeated rejected requests must not slide the recovery deadline.
	if existing, ok := c.entries[key]; ok && now.Before(existing.until) {
		// An already in-flight request can reveal rate limiting after another
		// request recorded 503. Preserve the stronger identity, not a new TTL.
		if status == http.StatusTooManyRequests && existing.status != status {
			existing.status = status
			c.entries[key] = existing
		}
		return
	}
	if len(c.entries) >= accountPoolCooldownCapacity {
		var oldestKey accountPoolCooldownKey
		var oldest time.Time
		for k, entry := range c.entries {
			if !now.Before(entry.until) {
				delete(c.entries, k)
				continue
			}
			if oldest.IsZero() || entry.until.Before(oldest) {
				oldestKey, oldest = k, entry.until
			}
		}
		if len(c.entries) >= accountPoolCooldownCapacity {
			delete(c.entries, oldestKey)
		}
	}
	c.entries[key] = accountPoolCooldownEntry{until: now.Add(accountPoolCooldownDuration), status: status}
}

// finishSelection only caches a genuinely empty initial selection. Request-local
// exclusions, capability fallback passes and transport failures are not proof
// that every account in the shared group/model/platform pool is unavailable.
func (c *accountPoolCooldown) finishSelection(key accountPoolCooldownKey, excludedIDs map[int64]struct{}, err *error) {
	if len(excludedIDs) != 0 || *err == nil {
		return
	}
	var cooldown *AccountPoolCooldownError
	if errors.As(*err, &cooldown) {
		c.mark(key, cooldown.StatusCode, time.Now())
		if cached := c.check(key, time.Now()); cached != nil {
			*err = cached
		}
		return
	}
	if !errors.Is(*err, errEmptyAccountPool) {
		return
	}
	c.mark(key, http.StatusServiceUnavailable, time.Now())
	if cached := c.check(key, time.Now()); cached != nil {
		*err = cached
	}
}

func (s *GatewayService) CheckAccountPoolCooldown(groupID *int64, model, platform string) error {
	return s.poolCooldown.check(poolCooldownKey(groupID, model, platform), time.Now())
}
func (s *GatewayService) MarkAccountPoolCooldown(groupID *int64, model, platform string, statusCode int) {
	s.poolCooldown.mark(poolCooldownKey(groupID, model, platform), statusCode, time.Now())
}
func (s *OpenAIGatewayService) CheckAccountPoolCooldown(groupID *int64, model, platform string) error {
	return s.poolCooldown.check(poolCooldownKey(groupID, model, NormalizeOpenAICompatiblePlatform(platform)), time.Now())
}
func (s *OpenAIGatewayService) MarkAccountPoolCooldown(groupID *int64, model, platform string, statusCode int) {
	s.poolCooldown.mark(poolCooldownKey(groupID, model, NormalizeOpenAICompatiblePlatform(platform)), statusCode, time.Now())
}

// MarkAccountPoolCooldownIfExhausted requires upstream-failure evidence for the
// entire schedulable pool, before request-specific model/capability filters.
func (s *GatewayService) MarkAccountPoolCooldownIfExhausted(ctx context.Context, groupID *int64, model, platform string, failedIDs map[int64]struct{}, statusCode int) {
	if len(failedIDs) == 0 || (statusCode != http.StatusServiceUnavailable && statusCode != http.StatusTooManyRequests) {
		return
	}
	group, resolvedID, err := s.checkClaudeCodeRestriction(ctx, groupID)
	if err != nil {
		return
	}
	resolvedPlatform, forced, err := s.resolvePlatform(ctx, resolvedID, group, model)
	if err != nil {
		return
	}
	accounts, _, err := s.listSchedulableAccounts(ctx, resolvedID, resolvedPlatform, forced)
	if err == nil && accountPoolFailuresCover(accounts, failedIDs) {
		s.MarkAccountPoolCooldown(groupID, model, platform, statusCode)
	}
}

func (s *OpenAIGatewayService) MarkAccountPoolCooldownIfExhausted(ctx context.Context, groupID *int64, model, platform string, failedIDs map[int64]struct{}, statusCode int) {
	if len(failedIDs) == 0 || (statusCode != http.StatusServiceUnavailable && statusCode != http.StatusTooManyRequests) {
		return
	}
	accounts, err := s.listSchedulableAccounts(ctx, groupID, platform)
	if err == nil && accountPoolFailuresCover(accounts, failedIDs) {
		s.MarkAccountPoolCooldown(groupID, model, platform, statusCode)
	}
}

func accountPoolFailuresCover(accounts []Account, failedIDs map[int64]struct{}) bool {
	// A now-empty pool can result from temporary unscheduling of every failed
	// account. A nonempty upstream-failure set still proves that exhaustion.
	for i := range accounts {
		if _, failed := failedIDs[accounts[i].ID]; !failed {
			return false
		}
	}
	return len(failedIDs) > 0
}

// Capture the caller's scope before composite routing or Claude-only fallback
// rewrites it, matching the keys supplied by protocol handlers.
func (s *GatewayService) requestPoolCooldownKey(ctx context.Context, groupID *int64, model string) (accountPoolCooldownKey, error) {
	platform, _ := ctx.Value(ctxkey.ForcePlatform).(string)
	if platform == "" {
		platform = PlatformAnthropic
		if groupID != nil {
			group, err := s.resolveGroupByID(ctx, *groupID)
			if err != nil {
				return accountPoolCooldownKey{}, err
			}
			platform = group.Platform
		}
	}
	return poolCooldownKey(groupID, model, platform), nil
}
