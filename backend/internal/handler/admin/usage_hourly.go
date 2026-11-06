package admin

import (
	"errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
	"time"
)

// Hourly is an admin-only, uncached aggregate; it does not expose usage-log details.
func (h *UsageHandler) Hourly(c *gin.Context) {
	start, err := time.Parse(time.RFC3339, c.Query("start_time"))
	if err != nil {
		response.BadRequest(c, "start_time must be RFC3339 with a timezone")
		return
	}
	end, err := time.Parse(time.RFC3339, c.Query("end_time"))
	if err != nil {
		response.BadRequest(c, "end_time must be RFC3339 with a timezone")
		return
	}
	filter := usagestats.HourlyUsageFilter{StartTime: start.UTC(), EndTime: end.UTC(), Model: c.Query("model")}
	if raw, exists := c.GetQuery("group_id"); exists {
		filter.GroupID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || filter.GroupID <= 0 {
			response.BadRequest(c, "group_id must be a positive integer")
			return
		}
	}
	rows, err := h.usageService.GetHourlyUsage(c.Request.Context(), filter)
	if errors.Is(err, service.ErrHourlyUsageRange) {
		response.BadRequest(c, "start_time must precede end_time by at most 31 days")
		return
	}
	if errors.Is(err, usagestats.ErrHourlyUsageLimit) {
		response.Error(c, http.StatusUnprocessableEntity, "Hourly usage exceeds 100000 rows; request a shorter range or filter")
		return
	}
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to query hourly usage")
		return
	}
	response.Success(c, gin.H{"start_time": filter.StartTime, "end_time": filter.EndTime, "granularity": "hour", "rows": rows})
}
