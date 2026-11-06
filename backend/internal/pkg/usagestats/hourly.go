package usagestats

import (
	"errors"
	"time"
)

const HourlyUsageMaxRows = 100000

var ErrHourlyUsageLimit = errors.New("hourly usage result exceeds row limit")

// HourlyUsageFilter selects a half-open instant range. GroupID zero means all groups.
type HourlyUsageFilter struct {
	StartTime time.Time
	EndTime   time.Time
	GroupID   int64
	Model     string
}

// HourlyUsageRow contains additive statistics, never request/user/key/account details.
// Bucket bounds are full UTC hours; query bounds clip partial edge buckets.
// DurationCount includes zero durations and excludes NULL durations.
type HourlyUsageRow struct {
	BucketStart         time.Time `json:"bucket_start"`
	BucketEnd           time.Time `json:"bucket_end"`
	GroupID             *int64    `json:"group_id"`
	Model               string    `json:"model"`
	Requests            int64     `json:"requests"`
	InputTokens         int64     `json:"input_tokens"`
	OutputTokens        int64     `json:"output_tokens"`
	CacheCreationTokens int64     `json:"cache_creation_tokens"`
	CacheReadTokens     int64     `json:"cache_read_tokens"`
	TotalTokens         int64     `json:"total_tokens"`
	Cost                float64   `json:"cost"`
	ActualCost          float64   `json:"actual_cost"`
	AccountCost         float64   `json:"account_cost"`
	DurationSumMs       int64     `json:"duration_sum_ms"`
	DurationCount       int64     `json:"duration_count"`
}
