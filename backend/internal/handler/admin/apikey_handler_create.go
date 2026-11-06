package admin

import (
	"context"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// AdminCreateUserAPIKeyRequest has the same options as user key creation.
// Ownership comes only from the URL, never from the acting administrator.
type AdminCreateUserAPIKeyRequest struct {
	Name          string   `json:"name" binding:"required"`
	GroupID       *int64   `json:"group_id"`
	CustomKey     *string  `json:"custom_key"`
	IPWhitelist   []string `json:"ip_whitelist"`
	IPBlacklist   []string `json:"ip_blacklist"`
	Quota         float64  `json:"quota"`
	ExpiresInDays *int     `json:"expires_in_days"`
	RateLimit5h   float64  `json:"rate_limit_5h"`
	RateLimit1d   float64  `json:"rate_limit_1d"`
	RateLimit7d   float64  `json:"rate_limit_7d"`
}

// CreateForUser creates a key without enabling user self-service in backend mode.
// POST /api/v1/admin/users/:id/api-keys
func (h *AdminAPIKeyHandler) CreateForUser(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	middleware.SetAuditAction(c, "admin.users.api_keys.create")
	actor, authenticated := middleware.GetAuthSubjectFromContext(c)
	if !authenticated || actor.UserID <= 0 {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	role, _ := middleware.GetUserRoleFromContext(c)
	if role != service.RoleAdmin {
		response.Forbidden(c, "Administrator access required")
		return
	}
	userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || userID <= 0 {
		response.BadRequest(c, "Invalid user ID")
		return
	}
	var req AdminCreateUserAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid API key creation request")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		response.BadRequest(c, "API key name must not be blank")
		return
	}
	// The shared coordinator defaults to observe-only for legacy clients.
	// Credential creation must never fall back to unkeyed execution.
	key, err := service.NormalizeIdempotencyKey(c.GetHeader("Idempotency-Key"))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if key == "" {
		response.BadRequest(c, "Idempotency-Key is required")
		return
	}
	if service.DefaultIdempotencyCoordinator() == nil || h.apiKeyCreator == nil {
		response.ErrorFrom(c, service.ErrIdempotencyStoreUnavail)
		return
	}
	user, err := h.adminService.GetUser(c.Request.Context(), userID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if user == nil {
		response.ErrorFrom(c, service.ErrUserNotFound)
		return
	}
	if !user.IsActive() {
		response.Forbidden(c, "Target user account is not active")
		return
	}
	middleware.SetAuditExtra(c, map[string]any{"target_user_id": userID})
	if req.GroupID != nil {
		middleware.SetAuditExtra(c, map[string]any{"group_id": *req.GroupID})
	}
	// FullPath contains :id, not the concrete target; include that target in
	// the fingerprint so an admin cannot replay one user's key for another.
	payload := struct {
		TargetUserID int64                        `json:"target_user_id"`
		Request      AdminCreateUserAPIKeyRequest `json:"request"`
	}{TargetUserID: userID, Request: req}
	scope := "admin.users.api_keys.create:" + adminActorScope(c)
	executeAdminIdempotentJSON(c, scope, payload,
		service.DefaultWriteIdempotencyTTL(), func(ctx context.Context) (any, error) {
			apiKey, err := h.apiKeyCreator.Create(ctx, userID, service.CreateAPIKeyRequest{
				Name: req.Name, GroupID: req.GroupID, CustomKey: req.CustomKey,
				IPWhitelist: req.IPWhitelist, IPBlacklist: req.IPBlacklist,
				Quota: req.Quota, ExpiresInDays: req.ExpiresInDays,
				RateLimit5h: req.RateLimit5h, RateLimit1d: req.RateLimit1d, RateLimit7d: req.RateLimit7d,
			})
			if err != nil {
				return nil, err
			}
			middleware.SetAuditExtra(c, map[string]any{"api_key_id": apiKey.ID})
			return dto.APIKeyFromService(apiKey).Localized(c.GetHeader("Accept-Language")), nil
		})
}
