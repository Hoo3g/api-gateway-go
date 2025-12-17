package middleware

import (
	"api-gateway-go/internal/cache"
	"api-gateway-go/internal/config"
	"api-gateway-go/internal/dto"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	UserInfoKey  = "userInfo"
	RequestIdKey = "requestId"

	AuthorizationHeader = "Authorization"
	BearerPrefix        = "Bearer "

	HeaderUserId    = "X-User-Id"
	HeaderUsername  = "X-Username"
	HeaderUserEmail = "X-User-Email"
	HeaderUserRoles = "X-User-Roles"
)

// handles jwt token validation
type AuthMiddleware struct {
	authServiceURL string
	validatePath   string
	httpClient     *http.Client
	cache          *cache.RedisCache
	logger         *zap.Logger
}

func NewAuthMiddleware(cfg *config.Config, cache *cache.RedisCache, logger *zap.Logger) *AuthMiddleware {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxConnsPerHost:     100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}
	return &AuthMiddleware{
		authServiceURL: cfg.Services.Authentication.URL,
		validatePath:   cfg.Services.Authentication.ValidateEndpoint,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.Services.Authentication.Timeout,
		},
		cache:  cache,
		logger: logger,
	}
}

func (m *AuthMiddleware) Handle() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			m.logger.Warn("Missing or invalid Authorization header",
				zap.String("path", c.Request.URL.Path))
			aboutWithError(c, http.StatusUnauthorized, "Missing or invalid Authorization header")
		}
	}
}

func aboutWithError(c *gin.Context, unauthorized int, s string) {

}

func (m *AuthMiddleware) extractToken(c *gin.Context) string {
	authHeader := c.GetHeader(AuthorizationHeader)

	if authHeader == "" {
		return ""
	}

	if !strings.HasPrefix(authHeader, BearerPrefix) {
		return ""
	}

	return strings.TrimPrefix(authHeader, BearerPrefix)
}

func (m *AuthMiddleware) validateToken(ctx context.Context, token string) (*dto.TokenValidationResponse, error) {
	url := m.authServiceURL + m.validatePath

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(AuthorizationHeader, BearerPrefix+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call auth service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("auth service returned %d: %s", resp.StatusCode, string(body))
	}

	var response dto.TokenValidationResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

func (m *AuthMiddleware) setUserContext(c *gin.Context, response *dto.TokenValidationResponse) {
	userInfo := &dto.UserInfo{
		UserID:    response.UserId,
		Username:  response.Username,
		Email:     response.Email,
		Roles:     response.Roles,
		ExpiresAt: response.ExpiresAt,
	}

	// Set user info in context
	c.Set(UserInfoKey, userInfo)

	// Add headers for downstream services
	c.Request.Header.Set(HeaderUserId, response.UserId)
	c.Request.Header.Set(HeaderUsername, response.Username)
	c.Request.Header.Set(HeaderUserEmail, response.Email)
	c.Request.Header.Set(HeaderUserRoles, strings.Join(response.Roles, ","))
}

// GetUserInfo retrieves user info from context
func GetUserInfo(c *gin.Context) (*dto.UserInfo, bool) {
	value, exists := c.Get(UserInfoKey)
	if !exists {
		return nil, false
	}
	userInfo, ok := value.(*dto.UserInfo)
	return userInfo, ok
}

func abortWithError(c *gin.Context, status int, message string) {
	requestID, _ := c.Get(RequestIdKey)
	c.AbortWithStatusJSON(status, dto.ErrorResponse{
		Status:    status,
		Message:   message,
		Path:      c.Request.URL.Path,
		Timestamp: time.Now().Unix(),
		RequestID: fmt.Sprintf("%v", requestID),
	})
}
