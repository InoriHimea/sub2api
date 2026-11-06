package config

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAIHTTPObservationRejectsInvalidSampling(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)
	for _, rate := range []float64{-0.1, 1.01, math.NaN(), math.Inf(1), math.Inf(-1)} {
		cfg.Gateway.OpenAIHTTPObservationSuccessSampleRate = rate
		require.ErrorContains(t, cfg.Validate(), "gateway.openai_http_observation_success_sample_rate")
	}
	for _, rate := range []float64{0, 0.25, 1} {
		cfg.Gateway.OpenAIHTTPObservationSuccessSampleRate = rate
		require.NoError(t, cfg.Validate())
	}
}
