package handler

import (
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/Wei-Shaw/sub2api/internal/util/logredact"
	"github.com/tidwall/gjson"
)

// selectRepresentativeFailure retains the complete selected error, including its
// body and headers. Terminal request errors must never be hidden by an earlier
// account failure; among retryable failures a rate limit is more actionable than
// unavailability. Equal-ranked failures keep the first response consistently.
func selectRepresentativeFailure(current, candidate *service.UpstreamFailoverError) *service.UpstreamFailoverError {
	if candidate == nil {
		return current
	}
	if current == nil || !candidate.ShouldRetryNextAccount() {
		return candidate
	}
	if !current.ShouldRetryNextAccount() {
		return current
	}
	if upstreamFailureRank(candidate) > upstreamFailureRank(current) {
		return candidate
	}
	return current
}

func upstreamFailureRank(err *service.UpstreamFailoverError) int {
	// Credential failures remain redacted by the protocol's existing renderer.
	// Prefer a real inference failure over an unusable account credential.
	if err.IsCredentialFailure() {
		return 0
	}
	switch err.StatusCode {
	case http.StatusTooManyRequests:
		return 3
	case http.StatusServiceUnavailable, 529:
		return 2
	default:
		return 1
	}
}

const representativeFailureMessageMaxBytes = 1024

// These rules supplement the shared key/value redactor only at the client
// boundary. Redact whole fragments before bounding output so truncation cannot
// turn a recognizable credential into an unrecognizable partial secret.
var representativeFailureSensitiveFragments = regexp.MustCompile(`(?i)\bbearer\s+[^\s,;'"<>]+|\b(?:sk-|org-|proj-|project-|projects/)[^\s,;'"<>]+|\b[a-z][a-z0-9+.-]*://[^\s'"<>]+|\bwww\.[^\s'"<>]+|[^\s,;'"<>]+@[^\s,;'"<>]+|\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::[0-9]+)?(?:/[^\s'"<>]+)?|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?|\[?[0-9a-f]*:[0-9a-f:]*:[0-9a-f:]+\]?(?::[0-9]+)?|\b[A-Za-z0-9_+/=-]{32,}\b`)

// Free-form account names, postal addresses and unlabelled project identifiers
// cannot be distinguished reliably from prose. Do not guess at their extent.
var representativeFailureAmbiguousIdentity = regexp.MustCompile(`(?i)\b(?:account|organization|organisation|project|address|email|credential|authorization|cookie|secret|token|api[_ -]?key)\b\s*(?:[:=]|\bis\b)\s*[^*\s]|\b(?:account|organization|organisation|project|address|email)\s+[^*\s]`)

// representativeFailureClientMessage exposes only the selected error's message,
// never its raw body, account credential failures, or structured quota details.
// Existing passthrough rules run before this default response mapping.
func representativeFailureClientMessage(err *service.UpstreamFailoverError, fallback string) string {
	if err == nil || err.IsCredentialFailure() || (err.StatusCode != http.StatusTooManyRequests && err.StatusCode != http.StatusServiceUnavailable) {
		return fallback
	}
	if gjson.GetBytes(err.ResponseBody, "error.details").Exists() {
		return fallback
	}
	// gjson.String also serializes objects and arrays. Only actual scalar
	// messages are eligible; nested JSON strings may contain account metadata.
	for _, path := range []string{"error.message", "detail", "message"} {
		value := gjson.GetBytes(err.ResponseBody, path)
		if !value.Exists() || strings.TrimSpace(value.String()) == "" {
			continue
		}
		if value.Type != gjson.String || strings.HasPrefix(strings.TrimSpace(value.Str), "{") || strings.HasPrefix(strings.TrimSpace(value.Str), "[") {
			return fallback
		}
		break
	}
	message := strings.TrimSpace(service.ExtractUpstreamErrorMessage(err.ResponseBody))
	// Bound sanitizer work as well as the final client message. Oversized or
	// malformed input is not safe to partially inspect.
	if message == "" || len(message) > 8192 || !utf8.ValidString(message) {
		return fallback
	}
	message = representativeFailureSensitiveFragments.ReplaceAllString(message, "***")
	if representativeFailureAmbiguousIdentity.MatchString(message) {
		return fallback
	}
	message = logredact.RedactText(service.SanitizeUpstreamErrorMessage(message), "api_key", "api-key", "token", "authorization", "cookie", "credentials", "secret", "account", "organization", "project", "email", "address")
	if len(message) > representativeFailureMessageMaxBytes {
		end := representativeFailureMessageMaxBytes
		for !utf8.RuneStart(message[end]) {
			end--
		}
		message = message[:end]
	}
	return message
}
