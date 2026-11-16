package handler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Exercise actual HTTP upstream responses through the shared failover state and
// client response writer; account ordering must not determine the final status.
func TestGroupFailureHTTPContract(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses []int
		want     int
	}{
		{"all_unavailable", []int{503, 503, 503}, 503},
		{"rate_limit_first", []int{429, 503, 503}, 429},
		{"rate_limit_middle", []int{503, 429, 503}, 429},
		{"rate_limit_last", []int{503, 503, 429}, 429},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				index := int(calls.Add(1)) - 1
				if index >= len(tc.statuses) {
					http.Error(w, "unexpected retry", 500)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				retryAfter := "31"
				if tc.statuses[index] == http.StatusTooManyRequests {
					retryAfter = "17"
				}
				w.Header().Set("Retry-After", retryAfter)
				w.WriteHeader(tc.statuses[index])
				fmt.Fprintf(w, `{"error":{"message":"fixture status %d"}}`, tc.statuses[index])
			}))
			defer upstream.Close()
			state := NewFailoverState(10, false)
			for index := range tc.statuses {
				response, err := http.Get(upstream.URL)
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				require.NoError(t, err)
				failure := &service.UpstreamFailoverError{StatusCode: response.StatusCode, ResponseBody: body, ResponseHeaders: response.Header}
				require.Equal(t, FailoverContinue, state.HandleFailoverError(context.Background(), &mockTempUnscheduler{}, int64(index+1), service.PlatformOpenAI, 0, failure))
			}
			require.Equal(t, FailoverExhausted, state.HandleSelectionExhausted(context.Background()))
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
			(&GatewayHandler{}).handleFailoverExhausted(c, state.LastFailoverErr, service.PlatformOpenAI, false)
			require.Equal(t, tc.want, recorder.Code)
			require.Contains(t, recorder.Body.String(), fmt.Sprintf("fixture status %d", tc.want))
			retryAfter := "31"
			if tc.want == http.StatusTooManyRequests {
				retryAfter = "17"
			}
			require.Equal(t, retryAfter, recorder.Header().Get("Retry-After"))
			require.Equal(t, int32(len(tc.statuses)), calls.Load())
		})
	}
}

type cooldownContractAccountRepo struct{ service.AccountRepository }

func (*cooldownContractAccountRepo) ListSchedulableByGroupIDAndPlatform(context.Context, int64, string) ([]service.Account, error) {
	return []service.Account{{ID: 1, Platform: service.PlatformAnthropic}}, nil
}

func TestGroupFailureCooldownHTTPContract(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":{"message":"fixture temporarily unavailable"}}`)
			}))
			defer upstream.Close()
			pool := service.NewGatewayService(&cooldownContractAccountRepo{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			groupID := int64(4711)
			router := gin.New()
			router.POST("/v1/messages", func(c *gin.Context) {
				c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), ctxkey.ForcePlatform, service.PlatformAnthropic))
				if err := pool.CheckAccountPoolCooldown(&groupID, "fixture-model", service.PlatformAnthropic); err != nil {
					failure := accountPoolSelectionFailure(c, err, pool, &groupID, "fixture-model", service.PlatformAnthropic, nil, nil)
					(&GatewayHandler{}).handleFailoverExhausted(c, failure, service.PlatformAnthropic, false)
					return
				}
				response, err := http.Get(upstream.URL)
				if err != nil {
					c.Status(http.StatusInternalServerError)
					return
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					c.Status(http.StatusInternalServerError)
					return
				}
				failure := &service.UpstreamFailoverError{StatusCode: response.StatusCode, ResponseBody: body}
				accountPoolSelectionFailure(c, service.ErrNoAvailableAccounts, pool, &groupID, "fixture-model", service.PlatformAnthropic, failure, map[int64]struct{}{1: {}})
				(&GatewayHandler{}).handleFailoverExhausted(c, failure, service.PlatformAnthropic, false)
			})
			gateway := httptest.NewServer(router)
			defer gateway.Close()
			for range 3 {
				response, err := http.Post(gateway.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"fixture-model"}`))
				require.NoError(t, err)
				_, err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				require.NoError(t, err)
				require.Equal(t, status, response.StatusCode)
				require.NotEmpty(t, response.Header.Get("Retry-After"))
			}
			require.Equal(t, int32(1), calls.Load(), "cooldown requests must not reach the upstream")
			otherGroup := groupID + 1
			require.NoError(t, pool.CheckAccountPoolCooldown(&otherGroup, "fixture-model", service.PlatformAnthropic))
			require.NoError(t, pool.CheckAccountPoolCooldown(&groupID, "other-model", service.PlatformAnthropic))
			require.NoError(t, pool.CheckAccountPoolCooldown(&groupID, "fixture-model", service.PlatformGemini))
		})
	}
}
