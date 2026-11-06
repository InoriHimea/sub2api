package service

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
)

// Selection belongs to the request sequence, not individual retry attempts or
// events. The zero-value configuration records no completion logs.
func (sequence *openAIHTTPSequence) selectCompletionSample(rate float64) {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	if sequence.sampleChosen {
		return
	}
	sequence.sampleChosen = true
	// Comparisons also fail closed for NaN if a caller bypasses config validation.
	if rate > 0 && rate <= 1 {
		sequence.sampleRate = rate
		sequence.sampled = rate == 1 || rand.Float64() < rate
	}
}

func sampledOpenAIStreamAttempt(c *gin.Context) *openAIHTTPAttempt {
	attempt := latestOpenAIHTTPAttempt(c)
	if attempt == nil || !attempt.sampled {
		return nil
	}
	attempt.mu.Lock()
	attempt.nativeStream = true
	attempt.data.CompletionSampled = true
	attempt.mu.Unlock()
	return attempt
}

// These marks are parser-processing times on the dispatch clock, not packet
// arrival timestamps. No payload, arbitrary upstream event type, or text is
// retained. Effective output uses the existing visible-output predicate; it is
// independent of the configured first_token_ms policy.
func (attempt *openAIHTTPAttempt) observeSSEDocument(data []byte, eventType string, terminal bool) {
	if attempt == nil {
		return
	}
	attempt.mu.Lock()
	needsFirst := attempt.data.FirstSSEEventMs < 0
	attempt.mu.Unlock()
	if !needsFirst && !terminal {
		return
	}
	now := time.Since(attempt.started).Milliseconds()
	valid := gjson.ValidBytes(data)
	attempt.mu.Lock()
	if valid && attempt.data.FirstSSEEventMs < 0 {
		attempt.data.FirstSSEEventMs = now
	}
	if terminal && valid {
		attempt.data.NativeTerminalEvent = safeObservationTerminal(eventType)
		attempt.data.TerminalEventMs = now
	}
	attempt.mu.Unlock()
}

func (attempt *openAIHTTPAttempt) observeOutput(progress, effective bool) {
	if attempt == nil || (!progress && !effective) {
		return
	}
	attempt.mu.Lock()
	if (!progress || attempt.data.FirstOutputProgressMs >= 0) && (!effective || attempt.data.FirstEffectiveOutputMs >= 0) {
		attempt.mu.Unlock()
		return
	}
	now := time.Since(attempt.started).Milliseconds()
	if progress && attempt.data.FirstOutputProgressMs < 0 {
		attempt.data.FirstOutputProgressMs = now
	}
	if effective && attempt.data.FirstEffectiveOutputMs < 0 {
		attempt.data.FirstEffectiveOutputMs = now
	}
	attempt.mu.Unlock()
}

// Embedding preserves Gin's optional interfaces and header/status semantics.
// Only real writes/flushes are timed: first-output staging and buffered appends
// are not downstream I/O. WriteString delegates directly to avoid double counts.
type observedOpenAIStreamWriter struct {
	gin.ResponseWriter
	attempt *openAIHTTPAttempt
}

func (writer *observedOpenAIStreamWriter) Write(p []byte) (int, error) {
	started := time.Now()
	n, err := writer.ResponseWriter.Write(p)
	writer.recordWrite(started, n, err)
	return n, err
}

func (writer *observedOpenAIStreamWriter) WriteString(value string) (int, error) {
	started := time.Now()
	n, err := writer.ResponseWriter.WriteString(value)
	writer.recordWrite(started, n, err)
	return n, err
}

func (writer *observedOpenAIStreamWriter) recordWrite(started time.Time, n int, err error) {
	elapsed := time.Since(started)
	attempt := writer.attempt
	attempt.mu.Lock()
	attempt.writeTime += elapsed
	d := &attempt.data
	d.DownstreamWriteCalls++
	d.DownstreamBytes += int64(n)
	d.DownstreamWriteDurationMs = attempt.writeTime.Milliseconds()
	if ms := elapsed.Milliseconds(); ms > d.DownstreamWriteMaxMs {
		d.DownstreamWriteMaxMs = ms
	}
	if n > 0 && d.FirstDownstreamWriteMs < 0 {
		d.FirstDownstreamWriteMs = time.Since(attempt.started).Milliseconds()
	}
	d.DownstreamWriteFailed = d.DownstreamWriteFailed || err != nil
	attempt.mu.Unlock()
}

func (writer *observedOpenAIStreamWriter) Flush() {
	started := time.Now()
	writer.ResponseWriter.Flush()
	elapsed := time.Since(started)
	attempt := writer.attempt
	attempt.mu.Lock()
	attempt.flushTime += elapsed
	d := &attempt.data
	d.DownstreamFlushCalls++
	d.DownstreamFlushDurationMs = attempt.flushTime.Milliseconds()
	if ms := elapsed.Milliseconds(); ms > d.DownstreamFlushMaxMs {
		d.DownstreamFlushMaxMs = ms
	}
	if d.FirstDownstreamFlushMs < 0 {
		d.FirstDownstreamFlushMs = time.Since(attempt.started).Milliseconds()
	}
	attempt.mu.Unlock()
}

func emitOpenAIHTTPCompletion(ctx context.Context, c *gin.Context, attempt *openAIHTTPAttempt, account *Account, outcome error) {
	if !attempt.sampled {
		return
	}
	attempt.mu.Lock()
	native := attempt.nativeStream
	attempt.mu.Unlock()
	if !native {
		return
	}
	d := sanitizedHTTPDiagnostics(attempt.snapshot())
	result := "incomplete"
	clientCanceled := c.Request != nil && c.Request.Context().Err() != nil
	switch {
	case clientCanceled || d.ClientDisconnected || errors.Is(outcome, context.Canceled) || d.NativeTerminalEvent == "response.canceled" || d.NativeTerminalEvent == "response.cancelled":
		result = "canceled"
	case outcome != nil || d.StreamFailed || d.DownstreamWriteFailed || d.NetworkError != "":
		result = "failed"
	case d.NativeTerminalEvent == "response.completed" || d.NativeTerminalEvent == "response.done":
		result = "complete"
	}
	attempt.sequence.mu.Lock()
	rate := attempt.sequence.sampleRate
	attempt.sequence.mu.Unlock()
	accountID := int64(0)
	if account != nil {
		accountID = account.ID
	}
	logger.FromContext(ctx).Info("openai.upstream_http_complete",
		zap.String("outcome", result), zap.Float64("sample_rate", rate),
		zap.Int64("account_id", accountID), zap.Any("upstream_http", d))
}
