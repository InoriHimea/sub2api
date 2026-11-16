package handler

import (
	"context"
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAccountPoolEvidenceExcludesProfitVetoesAndTerminalErrors(t *testing.T) {
	state := NewFailoverState(10, false)
	require.Nil(t, state.UpstreamFailedAccountIDs, "successful requests must not allocate evidence")
	state.RecordProfitVeto(1)
	require.Nil(t, state.UpstreamFailedAccountIDs)
	failure := &service.UpstreamFailoverError{StatusCode: http.StatusServiceUnavailable}
	require.Equal(t, FailoverContinue, state.HandleFailoverError(context.Background(), &mockTempUnscheduler{}, 2, service.PlatformOpenAI, 0, failure))
	require.Equal(t, map[int64]struct{}{2: {}}, state.UpstreamFailedAccountIDs)
	terminal := &service.UpstreamFailoverError{StatusCode: http.StatusBadRequest, Stage: service.GatewayFailureStageInference, Scope: service.GatewayFailureScopeRequest, NextAccountAction: service.NextAccountStop}
	recordAccountPoolFailure(&state.UpstreamFailedAccountIDs, 3, terminal)
	require.Equal(t, map[int64]struct{}{2: {}}, state.UpstreamFailedAccountIDs)
}
