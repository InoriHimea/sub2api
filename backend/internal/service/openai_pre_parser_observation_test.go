//go:build unit

package service

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestOpenAIHTTPObservationPreParserRejection(t *testing.T) {
	for _, tc := range []struct{ name, body, kind, code string }{
		{"known", `{"error":{"message":"BODY_SECRET_SENTINEL","type":"invalid_request_error","code":"invalid_value"}}`, "invalid_request_error", "invalid_value"},
		{"unknown", `{"error":{"message":"BODY_SECRET_SENTINEL","type":"TYPE_SECRET_SENTINEL","code":"CODE_SECRET_SENTINEL"}}`, "unknown", "unknown"},
		{"malformed", `not-json-BODY_SECRET_SENTINEL`, "unknown", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				_, _ = io.Copy(io.Discard, request.Body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := server.Client()
			defer client.CloseIdleConnections()
			upstream := &observationHTTPClient{client: client}
			svc := observationService(upstream)
			gin.SetMode(gin.TestMode)
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			core, logs := observer.New(zap.InfoLevel)
			ctx := logger.IntoContext(c.Request.Context(), zap.New(core).With(zap.String("request_id", "offline-pre-parser")))
			account := newOpenAIRejectedFieldTestAccount()
			account.Credentials["base_url"] = server.URL
			account.Credentials["api_key"] = "CREDENTIAL_SECRET_SENTINEL"
			_, err := svc.Forward(ctx, c, account, []byte(`{"model":"gpt-5.6-luna","input":[{"role":"user","content":"PROMPT_SECRET_SENTINEL"}],"stream":true}`))
			require.Error(t, err)
			require.EqualValues(t, 1, upstream.calls.Load(), "observation must not replay a rejection")
			entries := logs.FilterMessage("openai.upstream_http_failure").All()
			require.Len(t, entries, 1)
			fields := entries[0].ContextMap()
			require.EqualValues(t, account.ID, fields["account_id"])
			require.Equal(t, "offline-pre-parser", fields["request_id"])
			require.Equal(t, "pre_parser_http", fields["failure_stage"])
			d := fields["upstream_http"].(*UpstreamHTTPDiagnostics)
			require.Equal(t, 400, d.ResponseStatus)
			require.Equal(t, 1, d.Attempt)
			require.Equal(t, "HTTP/1.1", d.Protocol)
			require.GreaterOrEqual(t, d.WroteRequestMs, int64(0))
			require.GreaterOrEqual(t, d.FirstResponseByteMs, int64(0))
			require.Equal(t, int64(-1), d.FirstEffectiveOutputMs)
			require.False(t, d.StreamStateObserved)
			require.Empty(t, logs.FilterMessage("openai.upstream_http_complete").All())
			encoded, err := json.Marshal(fields)
			require.NoError(t, err)
			var record map[string]any
			require.NoError(t, json.Unmarshal(encoded, &record))
			diag := record["upstream_http"].(map[string]any)
			require.Equal(t, tc.kind, diag["rejection_type"])
			require.Equal(t, tc.code, diag["rejection_code"])
			for _, secret := range []string{"BODY_SECRET_SENTINEL", "TYPE_SECRET_SENTINEL", "CODE_SECRET_SENTINEL", "CREDENTIAL_SECRET_SENTINEL", "PROMPT_SECRET_SENTINEL"} {
				require.NotContains(t, string(encoded), secret)
			}
		})
	}
}
