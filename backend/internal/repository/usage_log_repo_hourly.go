package repository

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"time"
)

// GetHourlyUsage reads raw rows in one snapshot, so partial hours and NULL
// durations have the same meaning regardless of dashboard rollup freshness.
func (r *usageLogRepository) GetHourlyUsage(ctx context.Context, filter usagestats.HourlyUsageFilter) (result []usagestats.HourlyUsageRow, err error) {
	modelExpr := resolveModelDimensionExpressionWithAlias(usagestats.ModelSourceRequested, "ul")
	query := `SELECT date_trunc('hour', ul.created_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
 ul.group_id, ` + modelExpr + `, COUNT(*),
 COALESCE(SUM(ul.input_tokens),0), COALESCE(SUM(ul.output_tokens),0),
 COALESCE(SUM(ul.cache_creation_tokens),0), COALESCE(SUM(ul.cache_read_tokens),0),
 COALESCE(SUM(ul.input_tokens+ul.output_tokens+ul.cache_creation_tokens+ul.cache_read_tokens),0),
 COALESCE(SUM(ul.total_cost),0), COALESCE(SUM(ul.actual_cost),0),
 COALESCE(SUM(COALESCE(ul.account_stats_cost,ul.total_cost)*COALESCE(ul.account_rate_multiplier,1)),0),
 COALESCE(SUM(ul.duration_ms),0), COUNT(ul.duration_ms)
 FROM usage_logs ul WHERE ul.created_at >= $1 AND ul.created_at < $2`
	args := []any{hourlyPostgresBound(filter.StartTime), hourlyPostgresBound(filter.EndTime)}
	if filter.GroupID != 0 {
		args = append(args, filter.GroupID)
		query += fmt.Sprintf(" AND ul.group_id = $%d", len(args))
	}
	if filter.Model != "" {
		args = append(args, filter.Model)
		query += " AND " + modelExpr + fmt.Sprintf(" = $%d", len(args))
	}
	query += fmt.Sprintf(" GROUP BY 1,2,3 ORDER BY 1,2 NULLS FIRST,3 LIMIT %d", usagestats.HourlyUsageMaxRows+1)
	rows, err := r.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			result = nil
			err = closeErr
		}
	}()
	result = make([]usagestats.HourlyUsageRow, 0)
	for rows.Next() {
		if len(result) == usagestats.HourlyUsageMaxRows {
			return nil, usagestats.ErrHourlyUsageLimit
		}
		var row usagestats.HourlyUsageRow
		var group sql.NullInt64
		if err = rows.Scan(&row.BucketStart, &group, &row.Model, &row.Requests, &row.InputTokens, &row.OutputTokens, &row.CacheCreationTokens, &row.CacheReadTokens, &row.TotalTokens, &row.Cost, &row.ActualCost, &row.AccountCost, &row.DurationSumMs, &row.DurationCount); err != nil {
			return nil, err
		}
		row.BucketStart = row.BucketStart.UTC()
		row.BucketEnd = row.BucketStart.Add(time.Hour)
		if group.Valid {
			row.GroupID = &group.Int64
		}
		result = append(result, row)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// PostgreSQL timestamps lie on a microsecond grid. Ceiling both bounds preserves
// x >= start and x < end for stored x, instead of rounding away a fractional edge.
func hourlyPostgresBound(t time.Time) time.Time {
	if remainder := t.Nanosecond() % 1000; remainder != 0 {
		return t.Add(time.Duration(1000-remainder) * time.Nanosecond)
	}
	return t
}
