package service

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

// UpstreamHTTPDiagnostics contains only bounded, credential-free transport data.
// Stage times are milliseconds since this HTTP dispatch; -1 means unobserved.
// SequenceElapsedMs starts at the first dispatch, not ingress or authentication.
// FirstTokenMs retains the existing forward-start TTFT clock, not this clock.
// StreamStateObserved is false on surfaces that do not use the native Responses
// parser; reading EOF alone never implies a successful model response.
type UpstreamHTTPDiagnostics struct {
	Attempt                     int    `json:"attempt"`
	SequenceElapsedMs           int64  `json:"sequence_elapsed_ms"`
	TotalAttemptDurationMs      int64  `json:"total_attempt_duration_ms"`
	DurationMs                  int64  `json:"duration_ms"`
	RemainingDeadlineMs         int64  `json:"remaining_deadline_ms"`
	ConnectDoneMs               int64  `json:"connect_done_ms"`
	TLSHandshakeDoneMs          int64  `json:"tls_handshake_done_ms"`
	WroteRequestMs              int64  `json:"wrote_request_ms"`
	FirstResponseByteMs         int64  `json:"first_response_byte_ms"`
	ResponseHeadersMs           int64  `json:"response_headers_ms"`
	ConnectionObserved          bool   `json:"connection_observed"`
	ConnectionReused            bool   `json:"connection_reused"`
	ConnectionIdleMs            int64  `json:"connection_idle_ms"`
	ConnectionAcquisitions      int    `json:"connection_acquisitions"`
	RequestWrites               int    `json:"request_writes"`
	WriteFailed                 bool   `json:"write_failed"`
	Peer                        string `json:"peer,omitempty"`
	Protocol                    string `json:"protocol,omitempty"`
	ALPN                        string `json:"alpn,omitempty"`
	TLSStateObserved            bool   `json:"tls_state_observed"`
	TLSVerified                 bool   `json:"tls_verified"`
	ResponseStatus              int    `json:"response_status"`
	RejectionType               string `json:"rejection_type,omitempty"`
	RejectionCode               string `json:"rejection_code,omitempty"`
	BodyBytes                   int64  `json:"body_bytes"`
	EOFObserved                 bool   `json:"eof_observed"`
	NetworkError                string `json:"network_error,omitempty"`
	HTTP2StreamID               uint32 `json:"http2_stream_id,omitempty"`
	HTTP2ErrorCode              string `json:"http2_error_code,omitempty"`
	StreamStateObserved         bool   `json:"stream_state_observed"`
	FirstOutputProgressObserved bool   `json:"first_output_progress_observed"`
	FirstTokenMs                int64  `json:"first_token_ms_since_forward_start"`
	TerminalEvent               string `json:"terminal_event,omitempty"`
	StreamFailed                bool   `json:"stream_failed"`
	ClientDisconnected          bool   `json:"client_disconnected"`
	CompletionSampled           bool   `json:"completion_sampled"`
	FirstSSEEventMs             int64  `json:"first_sse_event_ms"`
	FirstOutputProgressMs       int64  `json:"first_output_progress_ms"`
	FirstEffectiveOutputMs      int64  `json:"first_effective_output_ms"`
	NativeTerminalEvent         string `json:"native_terminal_event,omitempty"`
	TerminalEventMs             int64  `json:"terminal_event_ms"`
	FirstDownstreamWriteMs      int64  `json:"first_downstream_write_ms"`
	FirstDownstreamFlushMs      int64  `json:"first_downstream_flush_ms"`
	DownstreamBytes             int64  `json:"downstream_bytes"`
	DownstreamWriteCalls        int64  `json:"downstream_write_calls"`
	DownstreamWriteDurationMs   int64  `json:"downstream_write_duration_ms"`
	DownstreamWriteMaxMs        int64  `json:"downstream_write_max_ms"`
	DownstreamFlushCalls        int64  `json:"downstream_flush_calls"`
	DownstreamFlushDurationMs   int64  `json:"downstream_flush_duration_ms"`
	DownstreamFlushMaxMs        int64  `json:"downstream_flush_max_ms"`
	DownstreamWriteFailed       bool   `json:"downstream_write_failed"`
}

type openAIHTTPObservationKey struct{}

const opsOpenAIHTTPObservationKey = "ops_openai_http_observation"

type openAIHTTPSequence struct {
	mu           sync.Mutex
	started      time.Time
	attempts     int
	completed    time.Duration
	latest       *openAIHTTPAttempt
	sampleChosen bool
	sampled      bool
	sampleRate   float64
}

type openAIHTTPAttempt struct {
	mu           sync.Mutex
	sequence     *openAIHTTPSequence
	started      time.Time
	ended        time.Time
	data         UpstreamHTTPDiagnostics
	sampled      bool
	nativeStream bool
	writeTime    time.Duration
	flushTime    time.Duration
}

func withOpenAIHTTPObservation(ctx context.Context, c *gin.Context) (context.Context, *openAIHTTPSequence, int) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil {
		return ctx, nil, 0
	}
	var sequence *openAIHTTPSequence
	if value, ok := c.Get(opsOpenAIHTTPObservationKey); ok {
		sequence, _ = value.(*openAIHTTPSequence)
	}
	if sequence == nil {
		sequence = &openAIHTTPSequence{}
		c.Set(opsOpenAIHTTPObservationKey, sequence)
	}
	sequence.mu.Lock()
	before := sequence.attempts
	sequence.mu.Unlock()
	return context.WithValue(ctx, openAIHTTPObservationKey{}, sequence), sequence, before
}

func beginOpenAIHTTPAttempt(request *http.Request) (*http.Request, *openAIHTTPAttempt) {
	sequence, _ := request.Context().Value(openAIHTTPObservationKey{}).(*openAIHTTPSequence)
	if sequence == nil {
		return request, nil
	}
	now := time.Now()
	attempt := &openAIHTTPAttempt{sequence: sequence, started: now}
	attempt.data = UpstreamHTTPDiagnostics{
		RemainingDeadlineMs: -1, ConnectDoneMs: -1, TLSHandshakeDoneMs: -1,
		WroteRequestMs: -1, FirstResponseByteMs: -1, ResponseHeadersMs: -1,
		ConnectionIdleMs: -1, FirstTokenMs: -1,
		FirstSSEEventMs: -1, FirstOutputProgressMs: -1, FirstEffectiveOutputMs: -1,
		TerminalEventMs: -1, FirstDownstreamWriteMs: -1, FirstDownstreamFlushMs: -1,
	}
	if deadline, ok := request.Context().Deadline(); ok {
		remaining := time.Until(deadline).Milliseconds()
		if remaining < 0 {
			remaining = 0
		}
		attempt.data.RemainingDeadlineMs = remaining
	}
	sequence.mu.Lock()
	if sequence.started.IsZero() {
		sequence.started = now
	}
	sequence.attempts++
	attempt.data.Attempt = sequence.attempts
	attempt.sampled = sequence.sampled
	sequence.latest = attempt
	sequence.mu.Unlock()
	trace := &httptrace.ClientTrace{
		ConnectDone: func(_, _ string, _ error) {
			attempt.mu.Lock()
			attempt.data.ConnectDoneMs = time.Since(now).Milliseconds()
			attempt.mu.Unlock()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, _ error) {
			attempt.mu.Lock()
			attempt.data.TLSHandshakeDoneMs = time.Since(now).Milliseconds()
			attempt.data.TLSStateObserved = true
			attempt.data.TLSVerified = len(state.VerifiedChains) > 0
			attempt.data.ALPN = safeObservationALPN(state.NegotiatedProtocol)
			attempt.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			attempt.mu.Lock()
			attempt.data.ConnectionObserved = true
			attempt.data.ConnectionAcquisitions++
			attempt.data.ConnectionReused = info.Reused
			attempt.data.ConnectionIdleMs = info.IdleTime.Milliseconds()
			attempt.data.Peer = safeObservationPeer(info.Conn.RemoteAddr().String())
			attempt.mu.Unlock()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			attempt.mu.Lock()
			attempt.data.RequestWrites++
			attempt.data.WroteRequestMs = time.Since(now).Milliseconds()
			attempt.data.WriteFailed = info.Err != nil
			attempt.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			attempt.mu.Lock()
			if attempt.data.FirstResponseByteMs < 0 {
				attempt.data.FirstResponseByteMs = time.Since(now).Milliseconds()
			}
			attempt.mu.Unlock()
		},
	}
	return request.WithContext(httptrace.WithClientTrace(request.Context(), trace)), attempt
}

func completeOpenAIHTTPDispatch(attempt *openAIHTTPAttempt, response *http.Response, err error) (*http.Response, error) {
	if attempt == nil {
		return response, err
	}
	attempt.mu.Lock()
	if response != nil {
		attempt.data.ResponseHeadersMs = time.Since(attempt.started).Milliseconds()
		attempt.data.Protocol = safeObservationProtocol(response.Proto)
		attempt.data.ResponseStatus = response.StatusCode
		if response.TLS != nil {
			attempt.data.TLSStateObserved = true
			attempt.data.ALPN = safeObservationALPN(response.TLS.NegotiatedProtocol)
			attempt.data.TLSVerified = len(response.TLS.VerifiedChains) > 0
		}
	}
	attempt.observeErrorLocked(err)
	attempt.mu.Unlock()
	if response != nil && response.Body != nil {
		response.Body = &observedOpenAIHTTPBody{ReadCloser: response.Body, attempt: attempt}
	} else {
		attempt.finish()
	}
	return response, err
}

type observedOpenAIHTTPBody struct {
	io.ReadCloser
	attempt *openAIHTTPAttempt
}

func (body *observedOpenAIHTTPBody) Read(p []byte) (int, error) {
	n, err := body.ReadCloser.Read(p)
	body.attempt.mu.Lock()
	body.attempt.data.BodyBytes += int64(n)
	if err == io.EOF {
		body.attempt.data.EOFObserved = true
	} else {
		body.attempt.observeErrorLocked(err)
	}
	body.attempt.mu.Unlock()
	return n, err
}

func (body *observedOpenAIHTTPBody) Close() error {
	err := body.ReadCloser.Close()
	body.attempt.finish()
	return err
}

func (attempt *openAIHTTPAttempt) finish() {
	attempt.mu.Lock()
	if !attempt.ended.IsZero() {
		attempt.mu.Unlock()
		return
	}
	attempt.ended = time.Now()
	duration := attempt.ended.Sub(attempt.started)
	attempt.sequence.mu.Lock()
	attempt.sequence.completed += duration
	attempt.sequence.mu.Unlock()
	attempt.mu.Unlock()
}

func (attempt *openAIHTTPAttempt) observeErrorLocked(err error) {
	if err == nil {
		return
	}
	var streamError http2.StreamError
	if errors.As(err, &streamError) {
		attempt.data.HTTP2StreamID = streamError.StreamID
		attempt.data.HTTP2ErrorCode = safeObservationHTTP2Code(streamError.Code.String())
		attempt.data.NetworkError = "http2_stream_error"
		return
	}
	switch {
	case errors.Is(err, context.Canceled):
		attempt.data.NetworkError = "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		attempt.data.NetworkError = "deadline_exceeded"
	case errors.Is(err, io.ErrUnexpectedEOF):
		attempt.data.NetworkError = "unexpected_eof"
	default:
		// The standard library has an unexported HTTP/2 stream-error type. Only
		// extract its numeric stream ID and known code, never its original text.
		text := err.Error()
		if offset := strings.Index(text, "stream error: stream ID "); offset >= 0 {
			rest := text[offset+len("stream error: stream ID "):]
			id, tail, ok := strings.Cut(rest, "; ")
			if parsed, parseErr := strconv.ParseUint(id, 10, 32); ok && parseErr == nil {
				code, _, _ := strings.Cut(tail, ";")
				if code = safeObservationHTTP2Code(code); code != "" {
					attempt.data.HTTP2StreamID = uint32(parsed)
					attempt.data.HTTP2ErrorCode = code
					attempt.data.NetworkError = "http2_stream_error"
					return
				}
			}
		}
		if strings.Contains(text, "http2: client connection lost") {
			attempt.data.NetworkError = "http2_connection_lost"
		} else {
			attempt.data.NetworkError = "transport_error"
		}
	}
}

func (attempt *openAIHTTPAttempt) snapshot() *UpstreamHTTPDiagnostics {
	attempt.mu.Lock()
	copy := attempt.data
	ended := attempt.ended
	if ended.IsZero() {
		copy.DurationMs = time.Since(attempt.started).Milliseconds()
	} else {
		copy.DurationMs = ended.Sub(attempt.started).Milliseconds()
	}
	attempt.mu.Unlock()
	attempt.sequence.mu.Lock()
	copy.SequenceElapsedMs = time.Since(attempt.sequence.started).Milliseconds()
	copy.TotalAttemptDurationMs = attempt.sequence.completed.Milliseconds()
	attempt.sequence.mu.Unlock()
	if ended.IsZero() {
		copy.TotalAttemptDurationMs += copy.DurationMs
	}
	return &copy
}

func latestOpenAIHTTPAttempt(c *gin.Context) *openAIHTTPAttempt {
	if c == nil {
		return nil
	}
	value, _ := c.Get(opsOpenAIHTTPObservationKey)
	sequence, _ := value.(*openAIHTTPSequence)
	if sequence == nil {
		return nil
	}
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	return sequence.latest
}

func snapshotOpenAIHTTPAttempt(c *gin.Context) *UpstreamHTTPDiagnostics {
	if attempt := latestOpenAIHTTPAttempt(c); attempt != nil {
		return attempt.snapshot()
	}
	return nil
}

func observeOpenAIHTTPStream(c *gin.Context, terminal string, failed, outputProgress, disconnected bool, firstTokenMs *int) {
	attempt := latestOpenAIHTTPAttempt(c)
	if attempt == nil {
		return
	}
	attempt.mu.Lock()
	attempt.data.StreamStateObserved = true
	attempt.data.TerminalEvent = safeObservationTerminal(terminal)
	attempt.data.StreamFailed = failed
	attempt.data.FirstOutputProgressObserved = outputProgress
	attempt.data.ClientDisconnected = disconnected
	if firstTokenMs != nil && *firstTokenMs >= 0 {
		attempt.data.FirstTokenMs = int64(*firstTokenMs)
	}
	attempt.mu.Unlock()
}

func finishOpenAIHTTPObservation(ctx context.Context, c *gin.Context, sequence *openAIHTTPSequence, attemptsBefore int, account *Account, outcome error) {
	if sequence == nil {
		return
	}
	sequence.mu.Lock()
	attempt := sequence.latest
	count := sequence.attempts
	sequence.mu.Unlock()
	if attempt == nil || count <= attemptsBefore {
		return
	}
	attempt.finish()
	var diagnostics *UpstreamHTTPDiagnostics
	var events []*OpsUpstreamErrorEvent
	if value, ok := c.Get(OpsUpstreamErrorsKey); ok {
		events, _ = value.([]*OpsUpstreamErrorEvent)
	}
	found := false
	for _, event := range events {
		if event != nil && event.HTTPDiagnostics != nil && event.HTTPDiagnostics.Attempt == count {
			if diagnostics == nil {
				diagnostics = attempt.snapshot()
			}
			event.HTTPDiagnostics = diagnostics
			found = true
		}
	}
	emitOpenAIHTTPCompletion(ctx, c, attempt, account, outcome)
	if outcome == nil {
		return
	}
	if diagnostics == nil {
		diagnostics = attempt.snapshot()
	}
	reason := diagnostics.NetworkError
	if reason == "" && diagnostics.EOFObserved && diagnostics.TerminalEvent == "" {
		reason = "missing_terminal_event"
	}
	clientCanceled := c.Request != nil && c.Request.Context().Err() != nil
	// Attribution only: do not change client bytes, status, retry eligibility,
	// cancellation propagation, or the existing upstream timeout policy.
	if !found && !clientCanceled && !diagnostics.ClientDisconnected && diagnostics.StreamStateObserved && diagnostics.StreamFailed &&
		reason != "" && reason != "context_canceled" && reason != "deadline_exceeded" {
		message := "Upstream response stream interrupted"
		setOpsUpstreamError(c, 0, message, "")
		event := OpsUpstreamErrorEvent{Platform: PlatformOpenAI, Kind: "stream_read_error", Stage: "response_body", Scope: "inference", Reason: reason, Message: message,
			ProxyID: opsUpstreamProxyID(account), ProxyName: opsUpstreamProxyName(account)}
		if account != nil {
			event.AccountID = account.ID
		}
		appendOpsUpstreamError(c, event)
	}
	stage := "pre_response"
	switch {
	case diagnostics.StreamStateObserved:
		stage = "response_stream"
	case diagnostics.ResponseHeadersMs >= 0 && diagnostics.ResponseStatus >= 300:
		stage = "pre_parser_http"
	case diagnostics.ResponseHeadersMs >= 0:
		stage = "response_body"
	}
	accountID := int64(0)
	if account != nil {
		accountID = account.ID
	}
	logger.FromContext(ctx).Warn("openai.upstream_http_failure",
		zap.Int64("account_id", accountID), zap.String("failure_stage", stage),
		zap.Any("upstream_http", sanitizedHTTPDiagnostics(diagnostics)))
}

// Read only the already bounded error buffer. Never retain arbitrary provider
// text, field names, URLs or headers; unrecognized classifications stay unknown.
func (attempt *openAIHTTPAttempt) observeRejection(body []byte) {
	kind, code := "unknown", "unknown"
	if gjson.ValidBytes(body) {
		kind = safeObservationRejection(gjson.GetBytes(body, "error.type").String())
		code = safeObservationRejection(gjson.GetBytes(body, "error.code").String())
	}
	attempt.mu.Lock()
	attempt.data.RejectionType = kind
	attempt.data.RejectionCode = code
	attempt.mu.Unlock()
}

func safeObservationRejection(value string) string {
	switch value {
	case "invalid_request_error", "authentication_error", "permission_error", "rate_limit_error", "server_error",
		"invalid_value", "unsupported_value", "unsupported_parameter", "missing_required_parameter",
		"model_not_found", "context_length_exceeded", "insufficient_quota", "rate_limit_exceeded",
		"invalid_api_key", "content_policy_violation":
		return value
	default:
		return "unknown"
	}
}

func safeObservationPeer(value string) string {
	host, port, err := net.SplitHostPort(value)
	ip := net.ParseIP(host)
	if err != nil || ip == nil {
		return ""
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return ""
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(n))
}

func safeObservationProtocol(value string) string {
	switch value {
	case "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0":
		return value
	}
	return ""
}
func safeObservationALPN(value string) string {
	switch value {
	case "http/1.1", "h2", "h3":
		return value
	}
	return ""
}
func safeObservationTerminal(value string) string {
	switch value {
	case "response.completed", "response.done", "response.failed", "response.incomplete", "response.cancelled", "response.canceled", "error", "[DONE]":
		return value
	}
	return ""
}
func safeObservationHTTP2Code(value string) string {
	switch value {
	case "NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR", "SETTINGS_TIMEOUT", "STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM", "CANCEL", "COMPRESSION_ERROR", "CONNECT_ERROR", "ENHANCE_YOUR_CALM", "INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED":
		return value
	}
	return ""
}

func sanitizedHTTPDiagnostics(value *UpstreamHTTPDiagnostics) *UpstreamHTTPDiagnostics {
	if value == nil {
		return nil
	}
	copy := *value
	copy.Peer = safeObservationPeer(copy.Peer)
	copy.Protocol = safeObservationProtocol(copy.Protocol)
	copy.ALPN = safeObservationALPN(copy.ALPN)
	copy.TerminalEvent = safeObservationTerminal(copy.TerminalEvent)
	copy.NativeTerminalEvent = safeObservationTerminal(copy.NativeTerminalEvent)
	copy.HTTP2ErrorCode = safeObservationHTTP2Code(copy.HTTP2ErrorCode)
	if copy.RejectionType != "" {
		copy.RejectionType = safeObservationRejection(copy.RejectionType)
	}
	if copy.RejectionCode != "" {
		copy.RejectionCode = safeObservationRejection(copy.RejectionCode)
	}
	switch copy.NetworkError {
	case "", "http2_stream_error", "http2_connection_lost", "context_canceled", "deadline_exceeded", "unexpected_eof", "transport_error":
	default:
		copy.NetworkError = "transport_error"
	}
	return &copy
}
