package middleware

import (
	"api-gateway-go/internal/cache"
	"api-gateway-go/internal/config"
	"api-gateway-go/internal/dto"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type AuthzMiddleware struct {
	authzServiceURL     string
	checkPath           string
	permissionCheckPath string
	httpClient          *http.Client
	cache               *cache.RedisCache
	logger              *zap.Logger
}

func NewAuthzMiddleware(cfg *config.Config, cache *cache.RedisCache, logger *zap.Logger) *AuthzMiddleware {
	transport := &http.Transport{
		MaxIdleConns:        100,              // Total max idle connections
		MaxIdleConnsPerHost: 20,               // Max idle per host
		IdleConnTimeout:     90 * time.Second, // How long idle connections are kept
		DisableCompression:  false,            // Enable compression
		ForceAttemptHTTP2:   true,             // Enable HTTP/2
	}

	return &AuthzMiddleware{
		authzServiceURL:     cfg.Services.Authorization.URL,
		checkPath:           cfg.Services.Authorization.CheckEndpoint,
		permissionCheckPath: cfg.Services.Authorization.PermissionCheckEndpoint,
		httpClient: &http.Client{
			Timeout:   cfg.Services.Authorization.Timeout,
			Transport: transport,
		},
		cache:  cache,
		logger: logger,
	}
}

func (m *AuthzMiddleware) RequireRoles(roles ...string) gin.HandlerFunc {
	return func(context *gin.Context) {
		userInfo, exists := GetUserInfo(context)
		if !exists {
			m.logger.Error("UserInfo not found in context")
			abortWithError(context, http.StatusUnauthorized, "Authentication required")
			return
		}

		if !userInfo.HasAnyRole(roles) {
			m.logger.Warn("Access denied - insufficient roles",
				zap.String("userId", userInfo.UserID),
				zap.Strings("userRoles", userInfo.Roles),
				zap.Strings("requiredRoles", roles))

			abortWithError(context, http.StatusForbidden, "Access denied - insufficient permissions")
			return
		}
		context.Next()
	}
}

func (m *AuthzMiddleware) RequirePermissions(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userInfo, exist := GetUserInfo(c)
		if !exist || userInfo == nil || userInfo.UserID == "" {
			m.logger.Error("UserInfo not found in context")
			abortWithError(c, http.StatusUnauthorized, "Authentication required")
			return
		}

		ctx := c.Request.Context()

		//check cache
		if hasPermission, found := m.cache.GetPermission(ctx, userInfo.UserID, permission); found {
			if !hasPermission {
				m.logger.Warn("Access denied(cached)",
					zap.String("userId", userInfo.UserID),
					zap.String("permission", permission))

				abortWithError(c, http.StatusForbidden,
					fmt.Sprintf("Insufficient permission: %s required", permission))
				return
			}
			m.logger.Debug("Permission granted (cached)",
				zap.String("userId", userInfo.UserID),
				zap.String("permission", permission))
			c.Next()
			return
		}

		// cache miss
		response, err := m.checkPermission(ctx, userInfo.UserID, permission)
		if err != nil {
			m.logger.Error("Permission check failed", zap.Error(err))
			abortWithError(c, http.StatusServiceUnavailable, "Authorization service unavailable")
			return
		}

		if response == nil {
			m.logger.Error("Authorization returned nil response")
			abortWithError(c, http.StatusServiceUnavailable, "Authorization service error")
		}

		//cache result with timeout
		cacheCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := m.cache.CachePermission(cacheCtx, userInfo.UserID, permission, response.HasPermission); err != nil {
			m.logger.Warn("Permission cache write failed",
				zap.Error(err),
				zap.String("userId", userInfo.UserID),
				zap.String("permission", permission))
		}

		if !response.HasPermission {
			m.logger.Warn("Access denied",
				zap.String("userId", userInfo.UserID),
				zap.String("permission", permission),
				zap.String("reason", response.Reason))
			abortWithError(c, http.StatusForbidden, "Forbidden")
			return
		}

		m.logger.Debug("Access granted",
			zap.String("userId", userInfo.UserID),
			zap.String("permission", permission))

		c.Next()
	}
}

func (m *AuthzMiddleware) checkPermission(ctx context.Context, userID, permission string) (*dto.PermissionCheckResponse, error) {
	url := m.authzServiceURL + m.permissionCheckPath

	reqBody := dto.PermissionCheckRequest{
		UserID:     userID,
		Permission: permission,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call authz service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authz service returned %d", resp.StatusCode)
	}

	var response dto.PermissionCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}
