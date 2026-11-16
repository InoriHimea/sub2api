package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type accountPoolCooldown interface {
	CheckAccountPoolCooldown(groupID *int64, model, platform string) error
	MarkAccountPoolCooldownIfExhausted(ctx context.Context, groupID *int64, model, platform string, failedIDs map[int64]struct{}, statusCode int)
}

// A failed request-specific selection is not proof of whole-pool exhaustion.
// Only actual upstream failures are supplied to the service's full-pool check.
// The cache stores status and expiry, never an upstream body or credentials.
func accountPoolSelectionFailure(c *gin.Context, err error, pool accountPoolCooldown, groupID *int64, model, platform string, representative *service.UpstreamFailoverError, failedIDs map[int64]struct{}) *service.UpstreamFailoverError {
	var cooldown *service.AccountPoolCooldownError
	if errors.As(err, &cooldown) {
		seconds := int64((cooldown.RetryAfter + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		headers := make(http.Header, 1)
		headers.Set("Retry-After", strconv.FormatInt(seconds, 10))
		return &service.UpstreamFailoverError{StatusCode: cooldown.StatusCode, ResponseHeaders: headers}
	}
	if representative == nil || !errors.Is(err, service.ErrNoAvailableAccounts) || (representative.StatusCode != http.StatusServiceUnavailable && representative.StatusCode != http.StatusTooManyRequests) {
		return nil
	}
	pool.MarkAccountPoolCooldownIfExhausted(c.Request.Context(), groupID, model, platform, failedIDs, representative.StatusCode)
	if errors.As(pool.CheckAccountPoolCooldown(groupID, model, platform), &cooldown) {
		seconds := int64((cooldown.RetryAfter + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		c.Header("Retry-After", strconv.FormatInt(seconds, 10))
	}
	return nil
}

// Keep upstream evidence separate from scheduling exclusions (profit vetoes,
// concurrency rejection, cached bindings and endpoint eligibility).
func recordAccountPoolFailure(failedIDs *map[int64]struct{}, accountID int64, failure *service.UpstreamFailoverError) {
	if failure == nil || !failure.ShouldRetryNextAccount() {
		return
	}
	if *failedIDs == nil {
		*failedIDs = make(map[int64]struct{})
	}
	(*failedIDs)[accountID] = struct{}{}
}
