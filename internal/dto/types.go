package dto

// TokenValidationRequest is sent to auth service
type TokenValidationRequest struct {
	Token string `json:"token"`
}

// TokenValidationResponse from auth service
type TokenValidationResponse struct {
	Valid     bool     `json:"valid"`
	UserID    string   `json:"userId"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	ExpiresAt int64    `json:"expiresAt"`
}

// AuthorizationRequest sent to authorization service
type AuthorizationRequest struct {
	UserID   string   `json:"userId"`
	Roles    []string `json:"roles"`
	Resource string   `json:"resource"`
	Method   string   `json:"method"`
}

// AuthorizationResponse from authorization service
type AuthorizationResponse struct {
	Authorized          bool     `json:"authorized"`
	Reason              string   `json:"reason,omitempty"`
	RequiredPermissions []string `json:"requiredPermissions,omitempty"`
}

// ErrorResponse is the standard error format
type ErrorResponse struct {
	Status    int    `json:"status"`
	Message   string `json:"message"`
	Path      string `json:"path"`
	Timestamp int64  `json:"timestamp"`
	RequestID string `json:"requestId,omitempty"`
}

// HealthResponse for health check endpoints
type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp int64             `json:"timestamp"`
	Services  map[string]string `json:"services,omitempty"`
}

// UserInfo holds authenticated user information
type UserInfo struct {
	UserID    string   `json:"userId"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	ExpiresAt int64    `json:"expiresAt"`
}

// HasRole checks if user has a specific role
func (u *UserInfo) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if user has any of the specified roles
func (u *UserInfo) HasAnyRole(roles []string) bool {
	for _, requiredRole := range roles {
		if u.HasRole(requiredRole) {
			return true
		}
	}
	return false
}

// RoutesConfig holds all routes configuration from YAML
type RoutesConfig struct {
	Routes []RouteGroup `yaml:"routes"`
}

// RouteGroup represents a group of routes with common configuration
type RouteGroup struct {
	Path           string        `yaml:"path"`
	Method         string        `yaml:"method"`
	Service        string        `yaml:"service"`
	Auth           bool          `yaml:"auth"`
	Roles          []string      `yaml:"roles"`
	Permission     string        `yaml:"permission"`
	RateLimit      string        `yaml:"rateLimit"`
	CircuitBreaker bool          `yaml:"circuitBreaker"`
	Public         bool          `yaml:"public"`
	Routes         []RouteConfig `yaml:"routes"`
}

// RouteConfig defines a single route configuration
type RouteConfig struct {
	Path           string   `yaml:"path"`
	Method         string   `yaml:"method"`
	Service        string   `yaml:"service"`
	Public         bool     `yaml:"public"`
	Auth           bool     `yaml:"auth"`
	Roles          []string `yaml:"roles"`
	Permission     string   `yaml:"permission"`
	RateLimit      string   `yaml:"rateLimit"`
	CircuitBreaker bool     `yaml:"circuitBreaker"`
	Upload         bool     `yaml:"upload"`
	Stream         bool     `yaml:"stream"`
	MaxFileSize    string   `yaml:"maxFileSize"`
	Description    string   `yaml:"description"`
}

// PermissionCheckRequest sent to authorization service
// POST /api/v1/permissions/check
type PermissionCheckRequest struct {
	UserID     string `json:"user_id"`
	Permission string `json:"permission"`
}

// PermissionCheckResponse from authorization service
type PermissionCheckResponse struct {
	HasPermission bool   `json:"has_permission"`
	Reason        string `json:"reason,omitempty"`
}

// Called by Authorization Service when user permissions change
type CacheInvalidationRequest struct {
	UserID string `json:"user_id"`
	Secret string `json:"secret"`
}
