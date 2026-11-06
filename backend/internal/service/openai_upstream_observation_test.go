//go:build unit

package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/net/http2"
)

// The adapter makes real network requests; it does not synthesize responses or
// echo observation fields. All TLS endpoints below are local httptest servers.
type observationHTTPClient struct {
	client *http.Client
	calls  atomic.Int32
}

func (upstream *observationHTTPClient) Do(request *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	upstream.calls.Add(1)
	return upstream.client.Do(request)
}
func (upstream *observationHTTPClient) DoWithTLS(request *http.Request, proxy string, accountID int64, concurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return upstream.Do(request, proxy, accountID, concurrency)
}

func observationTestContext(t *testing.T) (*gin.Context, *httptest.ResponseRecorder, context.Context, *openAIHTTPSequence, *observer.ObservedLogs) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	core, logs := observer.New(zap.WarnLevel)
	ctx := logger.IntoContext(c.Request.Context(), zap.New(core).With(zap.String("request_id", "local-observation-request")))
	ctx, sequence, before := withOpenAIHTTPObservation(ctx, c)
	require.Zero(t, before)
	return c, recorder, ctx, sequence, logs
}

func observationService(upstream HTTPUpstream) *OpenAIGatewayService {
	return &OpenAIGatewayService{httpUpstream: upstream, cfg: &config.Config{Gateway: config.GatewayConfig{MaxLineSize: defaultMaxLineSize}}}
}

func TestOpenAIHTTPObservationRealHTTP2ResetPersistsPartialStream(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n")
		w.(http.Flusher).Flush()
		// The real HTTP/2 server resets this stream with INTERNAL_ERROR after
		// visible output, rather than returning a fake error from a body stub.
		panic(http.ErrAbortHandler)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	transport := client.Transport.(*http.Transport)
	transport.ForceAttemptHTTP2 = true
	_, err := http2.ConfigureTransports(transport)
	require.NoError(t, err)
	defer transport.CloseIdleConnections()
	upstream := &observationHTTPClient{client: client}
	svc := observationService(upstream)
	c, recorder, ctx, _, logs := observationTestContext(t)
	account := newOpenAIRejectedFieldTestAccount()
	account.ID = 3
	account.Credentials["base_url"] = server.URL
	account.Credentials["api_key"] = "fixture-do-not-record"
	body := []byte(`{"model":"gpt-5.6-luna","input":[{"role":"user","content":"fixture-do-not-record"}],"stream":true}`)
	_, streamErr := svc.Forward(ctx, c, account, body)
	require.Error(t, streamErr)

	require.EqualValues(t, 1, upstream.calls.Load(), "observation must not replay a stream that already produced output")
	require.Contains(t, recorder.Body.String(), "partial")
	require.Contains(t, recorder.Body.String(), OpenAIUpstreamHTTP2StreamErrorCode)
	require.NotContains(t, recorder.Body.String(), "response.completed")
	require.NotContains(t, recorder.Body.String(), "fixture-do-not-record")
	require.Equal(t, http.StatusOK, recorder.Code, "only the existing SSE error is written; status is not rewritten")
	value, ok := c.Get(OpsUpstreamErrorsKey)
	require.True(t, ok)
	events := value.([]*OpsUpstreamErrorEvent)
	require.Len(t, events, 1, "one failed stream must not become multiple attempt errors")
	entry := &OpsInsertErrorLogInput{UpstreamErrors: events}
	require.NoError(t, sanitizeOpsUpstreamErrors(entry))
	require.NotNil(t, entry.UpstreamErrorsJSON)
	persisted, err := ParseOpsUpstreamErrors(*entry.UpstreamErrorsJSON)
	require.NoError(t, err)
	require.Len(t, persisted, 1)
	diagnostics := persisted[0].HTTPDiagnostics
	require.NotNil(t, diagnostics)
	require.Equal(t, "HTTP/2.0", diagnostics.Protocol)
	require.True(t, diagnostics.TLSVerified)
	require.Equal(t, "h2", diagnostics.ALPN)
	require.Equal(t, "http2_stream_error", diagnostics.NetworkError)
	require.Equal(t, "INTERNAL_ERROR", diagnostics.HTTP2ErrorCode)
	require.Positive(t, diagnostics.HTTP2StreamID)
	require.Equal(t, 1, diagnostics.Attempt)
	require.Equal(t, 1, diagnostics.RequestWrites)
	require.Equal(t, http.StatusOK, diagnostics.ResponseStatus)
	require.True(t, diagnostics.StreamStateObserved)
	require.True(t, diagnostics.FirstOutputProgressObserved)
	require.True(t, diagnostics.StreamFailed)
	require.False(t, diagnostics.ClientDisconnected)
	require.Empty(t, diagnostics.TerminalEvent)
	require.GreaterOrEqual(t, diagnostics.FirstTokenMs, int64(0))
	require.GreaterOrEqual(t, diagnostics.WroteRequestMs, int64(0))
	require.GreaterOrEqual(t, diagnostics.FirstResponseByteMs, diagnostics.WroteRequestMs)
	require.Equal(t, diagnostics.DurationMs, diagnostics.TotalAttemptDurationMs)
	require.NotEmpty(t, diagnostics.Peer)
	require.NotContains(t, *entry.UpstreamErrorsJSON, "fixture-do-not-record")
	require.Len(t, logs.All(), 1)
	require.Equal(t, "local-observation-request", logs.All()[0].ContextMap()["request_id"])
	require.Equal(t, "openai.upstream_http_failure", logs.All()[0].Message)
}

func TestOpenAIHTTPObservationRetrySnapshotsAndSuccessfulTerminalStayDistinct(t *testing.T) {
	var served atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		if served.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":{"code":"server_is_overloaded"}}`)
			return
		}
		// A missing/mislabelled Content-Type does not make valid SSE fail.
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"OK\"}\n\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"fixture\",\"status\":\"completed\",\"model\":\"gpt-5.6-luna\",\"usage\":{\"input_tokens\":8,\"output_tokens\":1}}}\n\n")
	}))
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	upstream := &observationHTTPClient{client: client}
	svc := observationService(upstream)
	c, recorder, ctx, sequence, logs := observationTestContext(t)
	account := &Account{ID: 3, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Concurrency: 1}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, strings.NewReader("synthetic"))
	require.NoError(t, err)
	first, err := svc.doOpenAIUpstream(request, "", account)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, first.Body)
	require.NoError(t, err)
	require.NoError(t, first.Body.Close())
	appendOpsUpstreamError(c, OpsUpstreamErrorEvent{Platform: PlatformOpenAI, AccountID: 3, Kind: "failover", Message: "upstream overloaded", UpstreamStatusCode: 503})
	value, _ := c.Get(OpsUpstreamErrorsKey)
	events := value.([]*OpsUpstreamErrorEvent)
	firstSnapshot := events[0].HTTPDiagnostics
	require.NotNil(t, firstSnapshot)
	require.Equal(t, 1, firstSnapshot.Attempt)
	require.Equal(t, 503, firstSnapshot.ResponseStatus)
	require.Equal(t, int64(-1), firstSnapshot.FirstTokenMs, "no output must remain unknown, not zero TTFT")
	require.False(t, firstSnapshot.StreamStateObserved)

	request, err = http.NewRequestWithContext(ctx, http.MethodPost, server.URL, strings.NewReader("synthetic"))
	require.NoError(t, err)
	second, err := svc.doOpenAIUpstream(request, "", account)
	require.NoError(t, err)
	_, err = svc.handleStreamingResponse(ctx, second, c, account, time.Now(), "gpt-5.6-luna", "gpt-5.6-luna")
	require.NoError(t, err)
	require.NoError(t, second.Body.Close())
	finishOpenAIHTTPObservation(ctx, c, sequence, 0, account, nil)
	last := snapshotOpenAIHTTPAttempt(c)
	require.EqualValues(t, 2, upstream.calls.Load(), "the two explicit dispatches must not be silently replayed")
	require.Equal(t, 2, last.Attempt)
	require.True(t, last.ConnectionReused)
	require.Equal(t, "HTTP/1.1", last.Protocol)
	require.Equal(t, "response.completed", last.TerminalEvent)
	require.True(t, last.FirstOutputProgressObserved)
	require.False(t, last.StreamFailed)
	require.GreaterOrEqual(t, last.TotalAttemptDurationMs, firstSnapshot.DurationMs+last.DurationMs)
	require.GreaterOrEqual(t, last.SequenceElapsedMs, last.TotalAttemptDurationMs)
	require.Equal(t, 503, firstSnapshot.ResponseStatus, "later success must not rewrite an earlier failed-attempt snapshot")
	require.Equal(t, 1, firstSnapshot.Attempt)
	require.Contains(t, recorder.Body.String(), "response.completed")
	require.Empty(t, logs.All(), "a recovered upstream attempt is not a failed final stream")
	entry := &OpsInsertErrorLogInput{UpstreamErrors: events}
	require.NoError(t, sanitizeOpsUpstreamErrors(entry))
	persisted, err := ParseOpsUpstreamErrors(*entry.UpstreamErrorsJSON)
	require.NoError(t, err)
	require.Equal(t, 1, persisted[0].HTTPDiagnostics.Attempt)
	require.Equal(t, 503, persisted[0].HTTPDiagnostics.ResponseStatus)
}

func TestOpenAIHTTPObservationCancellationDoesNotAcquireProviderAttribution(t *testing.T) {
	c, _, ctx, sequence, _ := observationTestContext(t)
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	request, attempt := beginOpenAIHTTPAttempt(request)
	response, err := completeOpenAIHTTPDispatch(attempt, nil, context.Canceled)
	require.Nil(t, response)
	require.ErrorIs(t, err, context.Canceled)
	observeOpenAIHTTPStream(c, "", true, false, true, nil)
	finishOpenAIHTTPObservation(ctx, c, sequence, 0, &Account{ID: 3, Platform: PlatformOpenAI}, err)
	_, hasProviderEvent := c.Get(OpsUpstreamErrorsKey)
	require.False(t, hasProviderEvent)
	diagnostics := snapshotOpenAIHTTPAttempt(c)
	require.Equal(t, "context_canceled", diagnostics.NetworkError)
	require.Equal(t, int64(-1), diagnostics.FirstTokenMs)
	require.Equal(t, int64(-1), diagnostics.ResponseHeadersMs)
	require.Equal(t, int64(-1), diagnostics.RemainingDeadlineMs)
	_ = request
}

func TestOpenAIHTTPObservationSnapshotSanitizationIsolatedFromCaller(t *testing.T) {
	value := &UpstreamHTTPDiagnostics{Attempt: 1, Peer: "user:secret@example.invalid:443", Protocol: "Bearer secret", ALPN: "secret", TerminalEvent: "private prompt", HTTP2ErrorCode: "secret", NetworkError: "token=secret"}
	entry := &OpsInsertErrorLogInput{UpstreamErrors: []*OpsUpstreamErrorEvent{{Kind: "request_error", Message: "upstream interrupted", HTTPDiagnostics: value}}}
	require.NoError(t, sanitizeOpsUpstreamErrors(entry))
	require.NotContains(t, *entry.UpstreamErrorsJSON, "secret")
	require.NotContains(t, *entry.UpstreamErrorsJSON, "private prompt")
	value.Attempt = 99
	persisted, err := ParseOpsUpstreamErrors(*entry.UpstreamErrorsJSON)
	require.NoError(t, err)
	require.Equal(t, 1, persisted[0].HTTPDiagnostics.Attempt)
	require.Equal(t, "transport_error", persisted[0].HTTPDiagnostics.NetworkError)
	require.Empty(t, persisted[0].HTTPDiagnostics.Protocol)
}

func TestOpenAIHTTPObservationTypedHTTP2ErrorSurvivesWrapping(t *testing.T) {
	_, _, ctx, _, _ := observationTestContext(t)
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	_, attempt := beginOpenAIHTTPAttempt(request)
	cause := http2.StreamError{StreamID: 7, Code: http2.ErrCodeProtocol}
	_, err := completeOpenAIHTTPDispatch(attempt, nil, errors.Join(errors.New("diagnostic wrapper"), cause))
	require.Error(t, err)
	data := attempt.snapshot()
	require.EqualValues(t, 7, data.HTTP2StreamID)
	require.Equal(t, "PROTOCOL_ERROR", data.HTTP2ErrorCode)
	encoded, err := json.Marshal(data)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "diagnostic wrapper")
}

func TestOpenAIHTTPObservationCleanEOFAfterOutputIsNotSuccess(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n")
	}))
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	upstream := &observationHTTPClient{client: client}
	svc := observationService(upstream)
	c, recorder, ctx, _, _ := observationTestContext(t)
	account := newOpenAIRejectedFieldTestAccount()
	account.Credentials["base_url"] = server.URL
	_, err := svc.Forward(ctx, c, account, []byte(`{"model":"gpt-5.6-luna","input":[{"role":"user","content":"synthetic"}],"stream":true}`))
	require.Error(t, err)
	require.EqualValues(t, 1, upstream.calls.Load())
	require.Contains(t, recorder.Body.String(), "partial")
	require.NotContains(t, recorder.Body.String(), "response.completed")
	value, ok := c.Get(OpsUpstreamErrorsKey)
	require.True(t, ok)
	events := value.([]*OpsUpstreamErrorEvent)
	require.Len(t, events, 1)
	require.Equal(t, "missing_terminal_event", events[0].Reason)
	diagnostics := events[0].HTTPDiagnostics
	require.True(t, diagnostics.EOFObserved)
	require.True(t, diagnostics.StreamFailed)
	require.Empty(t, diagnostics.NetworkError, "clean EOF is not an HTTP/2 reset")
	require.Empty(t, diagnostics.TerminalEvent)
	require.Empty(t, diagnostics.HTTP2ErrorCode)
}

func TestOpenAIHTTPObservationCredentialFailureDoesNotInheritHTTPAttempt(t *testing.T) {
	c, _, ctx, _, _ := observationTestContext(t)
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	_, attempt := beginOpenAIHTTPAttempt(request)
	_, _ = completeOpenAIHTTPDispatch(attempt, nil, context.Canceled)
	appendOpsUpstreamError(c, OpsUpstreamErrorEvent{Platform: PlatformOpenAI, Stage: " " + string(GatewayFailureStageAccountAuth) + " ", Message: "credentials unavailable", AccountID: 99})
	value, ok := c.Get(OpsUpstreamErrorsKey)
	require.True(t, ok)
	events := value.([]*OpsUpstreamErrorEvent)
	require.Len(t, events, 1)
	require.Nil(t, events[0].HTTPDiagnostics, "a later credential failure did not make the earlier HTTP dispatch")
}
