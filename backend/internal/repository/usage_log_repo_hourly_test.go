//go:build unit

package repository

import (
	"context"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestUsageHourlyRepositoryDiscardsPartialResultsOnDatabaseError(t *testing.T) {
	for _, kind := range []string{"query", "iteration", "scan", "close"} {
		t.Run(kind, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()
			query := mock.ExpectQuery("SELECT")
			if kind == "query" {
				query.WillReturnError(errors.New("query failed"))
			} else {
				rows := sqlmock.NewRows([]string{"bucket", "group", "model", "requests", "input", "output", "creation", "read", "total", "cost", "actual", "account", "sum", "count"}).AddRow(time.Now(), 5, "m", 1, 1, 2, 3, 4, 10, 1, 2, 3, 0, 1)
				switch kind {
				case "iteration":
					rows.AddRow(time.Now(), 5, "m", 1, 1, 2, 3, 4, 10, 1, 2, 3, 0, 1).RowError(1, errors.New("cursor failed"))
				case "scan":
					rows.AddRow(time.Now(), "not-an-id", "m", 1, 1, 2, 3, 4, 10, 1, 2, 3, 0, 1)
				case "close":
					rows.CloseError(errors.New("close failed"))
				}
				query.WillReturnRows(rows)
			}
			repo := newUsageLogRepositoryWithSQL(nil, db)
			got, err := repo.GetHourlyUsage(context.Background(), usagestats.HourlyUsageFilter{StartTime: time.Now(), EndTime: time.Now().Add(time.Hour)})
			require.Error(t, err)
			require.Nil(t, got)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
