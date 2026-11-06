//go:build unit

package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const observationTextFrame = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"OUTPUT_SECRET_SENTINEL\"}\n\n"
const observationCompletedFrame = "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":8,\"output_tokens\":2}}}\n\n"

func TestOpenAIHTTPObservationSampledCompletionRequiresAuthoritativeTerminal(t *testing.T) {
	cases := []struct {
		name, frames, outcome string
		complete, effective   bool
		rate                  float64
	}{
		{"complete", observationTextFrame + observationCompletedFrame, "complete", true, true, 1},
		{"complete_then_done", observationTextFrame + observationCompletedFrame + "data: [DONE]\n\n", "complete", true, true, 1},
		{"done_is_not_completion", observationTextFrame + "data: [DONE]\n\n", "", false, true, 1},
		{"eof_is_not_completion", observationTextFrame, "failed", false, true, 1},
		{"incomplete", observationTextFrame + "data: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\",\"usage\":{\"input_tokens\":8,\"output_tokens\":2}}}\n\n", "", false, true, 1},
		{"signature_is_not_effective_output", "data: {\"type\":\"response.output_item.added\",\"item\":{\"type\":\"reasoning\",\"summary\":[]}}\n\ndata: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"reasoning\",\"encrypted_content\":\"SIGNATURE_SECRET_SENTINEL\",\"summary\":[]}}\n\n" + observationCompletedFrame, "complete", true, false, 1},
		{"disabled", observationTextFrame + observationCompletedFrame, "", true, true, 0},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, tt.frames)
			}))
			defer server.Close()
			client := server.Client()
			defer client.CloseIdleConnections()
			upstream := &observationHTTPClient{client: client}
			svc := observationService(upstream)
			svc.cfg.Gateway.OpenAIHTTPObservationSuccessSampleRate = tt.rate
			c, recorder, _, _, _ := observationTestContext(t)
			core, logs := observer.New(zap.InfoLevel)
			ctx := logger.IntoContext(c.Request.Context(), zap.New(core).With(zap.String("request_id", "synthetic-completion")))
			account := newOpenAIRejectedFieldTestAccount()
			account.Credentials["base_url"] = server.URL
			account.Credentials["api_key"] = "CREDENTIAL_SECRET_SENTINEL"
			_, forwardErr := svc.Forward(ctx, c, account, []byte(`{"model":"gpt-5.6-luna","input":[{"role":"user","content":"PROMPT_SECRET_SENTINEL"}],"stream":true}`))
			entries := logs.FilterMessage("openai.upstream_http_complete").All()
			require.EqualValues(t, 1, upstream.calls.Load(), "observing must not replay an upstream request")
			if tt.rate == 0 {
				require.Empty(t, entries)
				require.NoError(t, forwardErr)
				require.Contains(t, recorder.Body.String(), "response.completed")
				return
			}
			require.Len(t, entries, 1)
			fields := entries[0].ContextMap()
			d := fields["upstream_http"].(*UpstreamHTTPDiagnostics)
			if tt.complete {
				require.NoError(t, forwardErr)
				require.Equal(t, "complete", fields["outcome"])
				require.Equal(t, "response.completed", d.NativeTerminalEvent)
				require.GreaterOrEqual(t, d.TerminalEventMs, d.FirstSSEEventMs)
				require.Contains(t, recorder.Body.String(), "response.completed")
				value, _ := c.Get(OpsUpstreamErrorsKey)
				require.Empty(t, value, "a successful stream must not create an Ops error row")
			} else {
				require.NotEqual(t, "complete", fields["outcome"])
			}
			if tt.outcome != "" {
				require.Equal(t, tt.outcome, fields["outcome"])
			}
			if tt.effective {
				require.GreaterOrEqual(t, d.FirstEffectiveOutputMs, int64(0))
			} else {
				require.Equal(t, int64(-1), d.FirstEffectiveOutputMs)
				require.GreaterOrEqual(t, d.FirstOutputProgressMs, int64(0))
			}
			require.True(t, d.CompletionSampled)
			require.Equal(t, "synthetic-completion", fields["request_id"])
			require.EqualValues(t, recorder.Body.Len(), d.DownstreamBytes)
			encoded, err := json.Marshal(fields)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), "SECRET_SENTINEL")
			require.NotContains(t, string(encoded), server.URL)
		})
	}
}

// The injected delay is in actual downstream writer methods, not the SSE
// staging buffer. It proves call-wall-time accounting, not a real lossy path.
type observationDelayedHTTPWriter struct {
	*httptest.ResponseRecorder
	writeErr error
}

func (w *observationDelayedHTTPWriter) Write(p []byte) (int, error) {
	time.Sleep(30 * time.Millisecond)
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return w.ResponseRecorder.Write(p)
}
func (w *observationDelayedHTTPWriter) WriteString(value string) (int, error) {
	time.Sleep(30 * time.Millisecond)
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return w.ResponseRecorder.WriteString(value)
}
func (w *observationDelayedHTTPWriter) Flush() {
	time.Sleep(30 * time.Millisecond)
	w.ResponseRecorder.Flush()
}

func TestOpenAIHTTPObservationMeasuresActualDownstreamCalls(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dst := &observationDelayedHTTPWriter{ResponseRecorder: httptest.NewRecorder()}
	c, _ := gin.CreateTestContext(dst)
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	ctx, sequence, _ := withOpenAIHTTPObservation(context.Background(), c)
	sequence.selectCompletionSample(1)
	request, err := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1/", nil)
	require.NoError(t, err)
	_, attempt := beginOpenAIHTTPAttempt(request)
	w := &observedOpenAIStreamWriter{ResponseWriter: c.Writer, attempt: attempt}
	_, err = w.Write([]byte("first"))
	require.NoError(t, err)
	_, err = w.WriteString("second")
	require.NoError(t, err)
	w.Flush()
	d := attempt.snapshot()
	require.Equal(t, "firstsecond", dst.Body.String())
	require.EqualValues(t, 2, d.DownstreamWriteCalls)
	require.EqualValues(t, 11, d.DownstreamBytes)
	require.GreaterOrEqual(t, d.DownstreamWriteDurationMs, int64(50))
	require.GreaterOrEqual(t, d.DownstreamWriteMaxMs, int64(25))
	require.EqualValues(t, 1, d.DownstreamFlushCalls)
	require.GreaterOrEqual(t, d.DownstreamFlushDurationMs, int64(25))
	require.False(t, d.DownstreamWriteFailed)

	dst.writeErr = io.ErrClosedPipe
	_, err = w.Write([]byte("not-sent"))
	require.ErrorIs(t, err, io.ErrClosedPipe)
	require.True(t, attempt.snapshot().DownstreamWriteFailed)
	require.EqualValues(t, 11, attempt.snapshot().DownstreamBytes)
}

func TestOpenAIHTTPObservationCancellationNeverCompletes(t *testing.T) {
	c, _, _, _, _ := observationTestContext(t)
	core, logs := observer.New(zap.InfoLevel)
	ctx, cancel := context.WithCancel(logger.IntoContext(context.Background(), zap.New(core)))
	c.Request = c.Request.WithContext(ctx)
	ctx, sequence, _ := withOpenAIHTTPObservation(ctx, c)
	sequence.selectCompletionSample(1)
	request, err := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1/", nil)
	require.NoError(t, err)
	_, attempt := beginOpenAIHTTPAttempt(request)
	require.Same(t, attempt, sampledOpenAIStreamAttempt(c))
	attempt.observeSSEDocument([]byte(`{"type":"response.completed"}`), "response.completed", true)
	observeOpenAIHTTPStream(c, "response.completed", false, true, false, nil)
	cancel()
	finishOpenAIHTTPObservation(ctx, c, sequence, 0, nil, context.Canceled)
	entries := logs.FilterMessage("openai.upstream_http_complete").All()
	require.Len(t, entries, 1)
	require.Equal(t, "canceled", entries[0].ContextMap()["outcome"])
	value, _ := c.Get(OpsUpstreamErrorsKey)
	require.Empty(t, value, "client cancellation is not provider failure")
}

func TestOpenAIHTTPObservationNonNativeAndSamplingStayScoped(t *testing.T) {
	c, _, _, _, _ := observationTestContext(t)
	core, logs := observer.New(zap.InfoLevel)
	ctx, sequence, _ := withOpenAIHTTPObservation(logger.IntoContext(context.Background(), zap.New(core)), c)
	sequence.selectCompletionSample(1)
	sequence.selectCompletionSample(0)
	require.True(t, sequence.sampled, "later account attempts must retain the request's sampling choice")
	request, err := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1/", nil)
	require.NoError(t, err)
	_, attempt := beginOpenAIHTTPAttempt(request)
	finishOpenAIHTTPObservation(ctx, c, sequence, 0, nil, nil)
	require.Empty(t, logs.FilterMessage("openai.upstream_http_complete").All(), "HTTP dispatch alone does not observe native SSE semantics")
	// Native completion observation is opt-in, not inferred from HTTP status.
	require.False(t, attempt.snapshot().CompletionSampled)
	seq := &openAIHTTPSequence{}
	seq.selectCompletionSample(0)
	seq.selectCompletionSample(1)
	require.False(t, seq.sampled)
}

func TestOpenAIHTTPObservationFailedWriterNeverCompletes(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, observationTextFrame+observationCompletedFrame)
	}))
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	upstream := &observationHTTPClient{client: client}
	svc := observationService(upstream)
	svc.cfg.Gateway.OpenAIHTTPObservationSuccessSampleRate = 1
	dst := &observationDelayedHTTPWriter{ResponseRecorder: httptest.NewRecorder(), writeErr: io.ErrClosedPipe}
	c, _ := gin.CreateTestContext(dst)
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	core, logs := observer.New(zap.InfoLevel)
	ctx := logger.IntoContext(c.Request.Context(), zap.New(core))
	account := newOpenAIRejectedFieldTestAccount()
	account.Credentials["base_url"] = server.URL
	result, err := svc.Forward(ctx, c, account, []byte(`{"model":"gpt-5.6-luna","input":"synthetic","stream":true}`))
	require.NoError(t, err, "preserve the existing drain-for-billing policy after client write failure")
	require.EqualValues(t, 2, result.Usage.OutputTokens)
	require.EqualValues(t, 1, upstream.calls.Load())
	require.Empty(t, dst.Body.String())
	entries := logs.FilterMessage("openai.upstream_http_complete").All()
	require.Len(t, entries, 1)
	require.Equal(t, "canceled", entries[0].ContextMap()["outcome"])
	d := entries[0].ContextMap()["upstream_http"].(*UpstreamHTTPDiagnostics)
	require.True(t, d.DownstreamWriteFailed)
	require.EqualValues(t, 0, d.DownstreamBytes)
	value, _ := c.Get(OpsUpstreamErrorsKey)
	require.Empty(t, value, "client writer failure must not create a provider failure")
}
