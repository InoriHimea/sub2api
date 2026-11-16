package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestRepresentativeFailureProtocolResponses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	openAI := &OpenAIGatewayHandler{}
	gateway := &GatewayHandler{}
	renderers := map[string]func(*gin.Context, *service.UpstreamFailoverError){
		"openai": func(c *gin.Context, err *service.UpstreamFailoverError) {
			openAI.handleFailoverExhausted(c, err, false)
		},
		"anthropic": func(c *gin.Context, err *service.UpstreamFailoverError) {
			openAI.handleAnthropicFailoverExhausted(c, err, false)
		},
		"messages": func(c *gin.Context, err *service.UpstreamFailoverError) {
			gateway.handleFailoverExhausted(c, err, service.PlatformAnthropic, false)
		},
		"chat": func(c *gin.Context, err *service.UpstreamFailoverError) {
			gateway.handleCCFailoverExhausted(c, err, false)
		},
		"responses": func(c *gin.Context, err *service.UpstreamFailoverError) {
			gateway.handleResponsesFailoverExhausted(c, err, false)
		},
		"gemini": gateway.handleGeminiFailoverExhausted,
	}
	for name, render := range renderers {
		t.Run(name, func(t *testing.T) {
			for _, statuses := range [][]int{{503, 503, 503}, {429, 503, 503}, {503, 429, 503}, {503, 503, 429}} {
				state := NewFailoverState(10, false)
				var expected *service.UpstreamFailoverError
				for i, status := range statuses {
					failure := &service.UpstreamFailoverError{
						StatusCode:      status,
						ResponseBody:    []byte(`{"error":{"message":"selected capacity message refresh_token=must-not-leak"}}`),
						ResponseHeaders: http.Header{"Retry-After": []string{"17"}},
					}
					if expected == nil || status == http.StatusTooManyRequests {
						expected = failure
					}
					require.Equal(t, FailoverContinue, state.HandleFailoverError(context.Background(), nil, int64(i+1), service.PlatformOpenAI, 0, failure))
				}
				require.Same(t, expected, state.LastFailoverErr, "body and headers must belong to the selected failure")
				require.Equal(t, FailoverExhausted, state.HandleSelectionExhausted(context.Background()))
				require.Len(t, state.FailedAccountIDs, 3, "exhausted accounts must never be re-enabled")
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				render(c, state.LastFailoverErr)
				require.Equal(t, expected.StatusCode, recorder.Code)
				require.Equal(t, "17", recorder.Header().Get("Retry-After"))
				require.Contains(t, recorder.Body.String(), "selected capacity message")
				require.NotContains(t, recorder.Body.String(), "must-not-leak")
			}
		})
	}
}

func TestRepresentativeFailureTerminalErrorWins(t *testing.T) {
	rateLimit := &service.UpstreamFailoverError{StatusCode: http.StatusTooManyRequests}
	terminal := &service.UpstreamFailoverError{StatusCode: http.StatusBadRequest, NextAccountAction: service.NextAccountStop}
	require.Same(t, terminal, selectRepresentativeFailure(rateLimit, terminal))
	require.Same(t, terminal, selectRepresentativeFailure(terminal, rateLimit))
}

func TestRepresentativeFailurePreservesPassthroughBodyAndHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rule := newBodyLimitPassthroughRule(http.StatusTooManyRequests, "selected rate limit")
	rule.ErrorCodes = []int{http.StatusTooManyRequests}
	h := newBodyLimitPassthroughHandler(t, rule)
	selected := &service.UpstreamFailoverError{
		StatusCode:      http.StatusTooManyRequests,
		ResponseBody:    []byte(`{"error":{"message":"rate limit"}}`),
		ResponseHeaders: http.Header{"Retry-After": []string{"23"}},
	}
	unavailable := &service.UpstreamFailoverError{
		StatusCode:      http.StatusServiceUnavailable,
		ResponseBody:    []byte(`{"error":{"message":"unavailable"}}`),
		ResponseHeaders: http.Header{"Retry-After": []string{"41"}},
	}
	for _, errors := range [][]*service.UpstreamFailoverError{{selected, unavailable}, {unavailable, selected}} {
		var representative *service.UpstreamFailoverError
		for _, failure := range errors {
			representative = selectRepresentativeFailure(representative, failure)
		}
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
		h.handleFailoverExhausted(c, representative, false)
		require.Equal(t, http.StatusTooManyRequests, recorder.Code)
		require.Equal(t, "23", recorder.Header().Get("Retry-After"))
		require.Contains(t, recorder.Body.String(), "selected rate limit")
		require.NotContains(t, recorder.Body.String(), "unavailable")
	}
}

func TestRepresentativeFailureClientMessageRedactsSensitiveFragments(t *testing.T) {
	const fallback = "generic upstream failure"
	tests := []struct {
		name    string
		message string
		secrets []string
	}{
		{"authorization bearer", "Capacity unavailable; Authorization: Bearer SYNTHETIC_AUTH_SECRET", []string{"SYNTHETIC_AUTH_SECRET"}},
		{"standalone bearer", "Capacity unavailable; Bearer SYNTHETIC_BEARER_SECRET", []string{"SYNTHETIC_BEARER_SECRET"}},
		{"mixed case bearer", "Capacity unavailable; bEaReR SYNTHETIC_CASE_SECRET", []string{"SYNTHETIC_CASE_SECRET"}},
		{"api credential", "Capacity unavailable for sk-synthetic-credential", []string{"sk-synthetic-credential"}},
		{"organization", "Capacity unavailable for organization org-synthetic-private", []string{"org-synthetic-private"}},
		{"project", "Capacity unavailable for project proj-synthetic-private", []string{"proj-synthetic-private"}},
		{"project reference", "Capacity unavailable for projects/synthetic-private", []string{"projects/synthetic-private"}},
		{"email", "Capacity unavailable for synthetic-owner@example.test", []string{"synthetic-owner", "example.test"}},
		{"url account info", "Capacity unavailable at https://user:synthetic-password@example.test/private?token=synthetic-query", []string{"synthetic-password", "example.test", "synthetic-query"}},
		{"ipv4 address", "Capacity unavailable at 192.0.2.12:8080", []string{"192.0.2.12"}},
		{"ipv6 address", "Capacity unavailable at [2001:db8::12]:8080", []string{"2001:db8::12"}},
		{"hostname", "Capacity unavailable at private-upstream.example.test:8080", []string{"private-upstream.example.test"}},
		{"opaque token", "Capacity unavailable for SyntheticOpaqueCredential0123456789abcdef", []string{"SyntheticOpaqueCredential0123456789abcdef"}},
		{"shared redactor", "Capacity unavailable; refresh_token=synthetic-refresh", []string{"synthetic-refresh"}},
	}
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		for _, tt := range tests {
			t.Run(http.StatusText(status)+"/"+tt.name, func(t *testing.T) {
				body, err := json.Marshal(map[string]any{"error": map[string]string{"message": tt.message}})
				require.NoError(t, err)
				message := representativeFailureClientMessage(&service.UpstreamFailoverError{StatusCode: status, ResponseBody: body}, fallback)
				require.Contains(t, message, "Capacity unavailable", "safe reason should survive fragment redaction")
				for _, secret := range tt.secrets {
					require.NotContains(t, message, secret)
				}
				require.True(t, utf8.ValidString(message))
				require.LessOrEqual(t, len(message), representativeFailureMessageMaxBytes)
			})
		}
	}
}

func TestRepresentativeFailureClientMessageSafeReasonsAndBounds(t *testing.T) {
	for _, message := range []string{
		"No capacity available for model gpt-5.4; please retry later.",
		"Rate limit reached: 100 requests per minute. Try again in 5 seconds.",
		"请求过多，请稍后重试。",
		strings.Repeat("容量", 700),
		strings.Repeat("a ", 511) + "x容量",
	} {
		body, err := json.Marshal(map[string]string{"message": message})
		require.NoError(t, err)
		got := representativeFailureClientMessage(&service.UpstreamFailoverError{StatusCode: http.StatusTooManyRequests, ResponseBody: body}, "fallback")
		require.True(t, utf8.ValidString(got))
		require.LessOrEqual(t, len(got), representativeFailureMessageMaxBytes)
		if len(message) <= representativeFailureMessageMaxBytes {
			require.Equal(t, message, got)
		} else {
			require.NotEmpty(t, got)
			require.True(t, strings.HasPrefix(message, got))
		}
	}
}

func TestRepresentativeFailureClientMessageUnsafeFallbacks(t *testing.T) {
	const fallback = "generic upstream failure"
	for _, body := range []string{
		`{"error":{"message":"Rate limit reached","details":[{"account":"synthetic-private"}]}}`,
		`{"error":{"message":{"account":"synthetic-private"}}}`,
		`{"detail":{"account":"synthetic-private"}}`,
		`{"message":["synthetic-private"]}`,
		`{"error":{"message":"{\"error\":{\"message\":\"synthetic-private\"}}"}}`,
		`{"message":"Capacity unavailable for account Jane Synthetic Doe"}`,
		`{"message":"Capacity unavailable; address: 123 Synthetic Street"}`,
		`{"message":"Capacity unavailable; project: synthetic-private"}`,
		`{"message":"Capacity unavailable; secret: synthetic private phrase"}`,
		`{"message":"` + strings.Repeat("容量", 3000) + ` Bearer SYNTHETIC_END_SECRET"}`,
		"{\"message\":\"Capacity unavailable \xff\"}",
	} {
		require.Equal(t, fallback, representativeFailureClientMessage(&service.UpstreamFailoverError{StatusCode: http.StatusServiceUnavailable, ResponseBody: []byte(body)}, fallback))
	}
	require.Equal(t, fallback, representativeFailureClientMessage(&service.UpstreamFailoverError{
		StatusCode:   http.StatusTooManyRequests,
		Stage:        service.GatewayFailureStageAccountAuth,
		ResponseBody: []byte(`{"message":"synthetic credential failure"}`),
	}, fallback))
}
