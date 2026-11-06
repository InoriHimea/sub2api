package service

import (
	"context"
	"errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"time"
)

var ErrHourlyUsageRange = errors.New("hourly usage requires start_time < end_time, at most 31 days, and a nonnegative group filter")

func (s *UsageService) GetHourlyUsage(ctx context.Context, filter usagestats.HourlyUsageFilter) ([]usagestats.HourlyUsageRow, error) {
	if filter.StartTime.IsZero() || filter.EndTime.IsZero() || !filter.StartTime.Before(filter.EndTime) || filter.EndTime.Sub(filter.StartTime) > 31*24*time.Hour || filter.GroupID < 0 {
		return nil, ErrHourlyUsageRange
	}
	filter.StartTime = filter.StartTime.UTC()
	filter.EndTime = filter.EndTime.UTC()
	return s.usageRepo.GetHourlyUsage(ctx, filter)
}
