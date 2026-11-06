//go:build unit

package service

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/net/http2"
)

// Delays wrap the actual loopback server writer. These are injected writer-call
// delays, not a claim that loopback reproduced an Internet loss/backpressure path.
type observationSmokeWriter struct{ http.ResponseWriter }

func (w observationSmokeWriter) Write(p []byte) (int, error) {
	time.Sleep(20 * time.Millisecond)
	return w.ResponseWriter.Write(p)
}
func (w observationSmokeWriter) Flush() {
	time.Sleep(20 * time.Millisecond)
	w.ResponseWriter.(http.Flusher).Flush()
}

func TestOpenAIHTTPObservationRealHTTPSuccessSmoke(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var baseline []byte
	for _, protocol := range []string{"h1", "h2"} {
		for _, rate := range []float64{0, 1} {
			name := protocol + "/disabled"
			if rate == 1 {
				name = protocol + "/sampled"
			}
			t.Run(name, func(t *testing.T) {
				releaseOutput := make(chan struct{})
				defer func() {
					select {
					case <-releaseOutput:
					default:
						close(releaseOutput)
					}
				}()
				var uploadBytes atomic.Int64
				upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n, _ := io.Copy(io.Discard, r.Body)
					uploadBytes.Store(n)
					// A response-header delay after consuming the request body makes
					// the local upload and response clocks separable in this fixture.
					time.Sleep(30 * time.Millisecond)
					w.Header().Set("Content-Type", "text/event-stream")
					// Fix the upstream lifecycle clock across requests: upstream
					// fills a missing completed timestamp from response.created.
					_, _ = io.WriteString(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"synthetic-fixed-id\",\"created_at\":1700000000}}\n\n")
					_, _ = io.WriteString(w, "data: {\"type\":\"response.output_item.added\",\"item\":{\"type\":\"reasoning\",\"summary\":[]}}\n\n")
					_, _ = io.WriteString(w, "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"reasoning\",\"encrypted_content\":\"SIGNATURE_SECRET_SENTINEL\",\"summary\":[]}}\n\n")
					w.(http.Flusher).Flush()
					select {
					case <-releaseOutput:
					case <-r.Context().Done():
						return
					}
					_, _ = io.WriteString(w, observationTextFrame+observationCompletedFrame+"data: [DONE]\n\n")
				}))
				upstream.EnableHTTP2 = protocol == "h2"
				upstream.StartTLS()
				defer upstream.Close()
				defer upstream.CloseClientConnections()
				client := upstream.Client()
				transport := client.Transport.(*http.Transport)
				transport.ForceAttemptHTTP2 = protocol == "h2"
				if protocol == "h2" {
					_, err := http2.ConfigureTransports(transport)
					require.NoError(t, err)
				}
				defer transport.CloseIdleConnections()
				adapter := &observationHTTPClient{client: client}
				svc := observationService(adapter)
				svc.cfg.Gateway.OpenAIHTTPObservationSuccessSampleRate = rate
				account := newOpenAIRejectedFieldTestAccount()
				account.Credentials["base_url"] = upstream.URL
				account.Credentials["api_key"] = "CREDENTIAL_SECRET_SENTINEL"
				core, logs := observer.New(zap.InfoLevel)
				finished := make(chan error, 1)
				ops := make(chan any, 1)
				router := gin.New()
				router.POST("/v1/responses", func(c *gin.Context) {
					body, err := io.ReadAll(c.Request.Body)
					if err != nil {
						finished <- err
						return
					}
					ctx := logger.IntoContext(c.Request.Context(), zap.New(core).With(zap.String("request_id", "offline-success-http-smoke")))
					_, err = svc.Forward(ctx, c, account, body)
					value, _ := c.Get(OpsUpstreamErrorsKey)
					ops <- value
					finished <- err
				})
				downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					router.ServeHTTP(observationSmokeWriter{w}, r)
				}))
				defer downstream.Close()
				input, err := json.Marshal(map[string]any{"model": "gpt-5.6-luna", "stream": true, "input": []any{map[string]any{"role": "user", "content": "PROMPT_SECRET_SENTINEL" + strings.Repeat("x", 32*1024)}}})
				require.NoError(t, err)
				httpClient := &http.Client{Timeout: 10 * time.Second}
				response, err := httpClient.Post(downstream.URL+"/v1/responses", "application/json", bytes.NewReader(input))
				require.NoError(t, err)
				defer response.Body.Close()
				require.Equal(t, 200, response.StatusCode)
				reader := bufio.NewReader(response.Body)
				var output bytes.Buffer
				for {
					line, readErr := reader.ReadString('\n')
					output.WriteString(line)
					require.NoError(t, readErr)
					if strings.Contains(line, "SIGNATURE_SECRET_SENTINEL") {
						break
					}
				}
				// The client has received structural/signature progress but no
				// effective text. Release text only after a visible boundary.
				require.NotContains(t, output.String(), "OUTPUT_SECRET_SENTINEL")
				time.Sleep(70 * time.Millisecond)
				close(releaseOutput)
				_, err = io.Copy(&output, reader)
				require.NoError(t, err)
				require.NoError(t, <-finished)
				require.Empty(t, <-ops)
				require.EqualValues(t, 1, adapter.calls.Load())
				require.Greater(t, uploadBytes.Load(), int64(32*1024))
				require.Contains(t, output.String(), "OUTPUT_SECRET_SENTINEL")
				require.Contains(t, output.String(), "response.completed")
				for _, payload := range sseDataPayloads(output.String()) {
					var event struct {
						Response *struct {
							CreatedAt int64 `json:"created_at"`
						} `json:"response"`
					}
					require.NoError(t, json.Unmarshal([]byte(payload), &event))
					if event.Response != nil {
						require.EqualValues(t, 1700000000, event.Response.CreatedAt, "sampling must retain the native response timestamp contract")
					}
				}
				entries := logs.FilterMessage("openai.upstream_http_complete").All()
				if rate == 0 {
					require.Empty(t, entries)
					baseline = append(baseline[:0], output.Bytes()...)
					return
				}
				require.Equal(t, baseline, output.Bytes(), "sampling must not alter downstream SSE bytes")
				require.Len(t, entries, 1)
				fields := entries[0].ContextMap()
				d := fields["upstream_http"].(*UpstreamHTTPDiagnostics)
				require.Equal(t, "complete", fields["outcome"])
				require.Equal(t, "response.completed", d.NativeTerminalEvent)
				require.GreaterOrEqual(t, d.WroteRequestMs, int64(0))
				require.GreaterOrEqual(t, d.FirstResponseByteMs-d.WroteRequestMs, int64(20))
				require.GreaterOrEqual(t, d.FirstOutputProgressMs, d.FirstSSEEventMs)
				require.GreaterOrEqual(t, d.FirstEffectiveOutputMs-d.FirstOutputProgressMs, int64(50))
				require.GreaterOrEqual(t, d.TerminalEventMs, d.FirstEffectiveOutputMs)
				require.GreaterOrEqual(t, d.DownstreamWriteDurationMs, int64(15))
				require.GreaterOrEqual(t, d.DownstreamFlushDurationMs, int64(15))
				require.EqualValues(t, output.Len(), d.DownstreamBytes)
				if protocol == "h2" {
					require.Equal(t, "HTTP/2.0", d.Protocol)
				} else {
					require.Equal(t, "HTTP/1.1", d.Protocol)
				}
				encoded, err := json.Marshal(fields)
				require.NoError(t, err)
				require.NotContains(t, string(encoded), "SECRET_SENTINEL")
				t.Log("SUCCESS_OBSERVATION_SMOKE", string(encoded))
			})
		}
	}
}
