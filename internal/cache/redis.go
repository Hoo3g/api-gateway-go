package cache

import (
	"api-gateway-go/internal/config"
	"api-gateway-go/internal/dto"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	tokenValidationPrefix = "token:validation"
	authorizationPrefix   = "authz:"
	permissionPrefix      = "perm:"
)

type RedisCache struct {
	client   *redis.Client
	cfg      *config.CacheConfig
	logger   *zap.Logger
	tokenTTL time.Duration
	authzTTL time.Duration
}

// Create a new redis instance
func NewRedisCache(redisCfg *config.RedisConfig,
	cacheCfg *config.CacheConfig,
	logger *zap.Logger) (*RedisCache, error) {

	client := redis.NewClient(&redis.Options{
		Addr:     redisCfg.Addr(),
		Password: redisCfg.Password,
		DB:       redisCfg.DB,
		PoolSize: redisCfg.PoolSize,
	})

	//Test connect
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info("Connected to Redis",
		zap.String("addr", redisCfg.Addr()),
		zap.Int("db", redisCfg.DB))

	return &RedisCache{
		client:   client,
		cfg:      cacheCfg,
		logger:   logger,
		tokenTTL: time.Duration(cacheCfg.TokenTTL) * time.Second,
		authzTTL: time.Duration(cacheCfg.AuthzTTL) * time.Second,
	}, nil
}

// Close redis
func (c *RedisCache) Close() error {
	return c.client.Close()
}

// Check if redis is available
func (c *RedisCache) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Caches a token validation response
func (c *RedisCache) CacheTokenValidation(ctx context.Context,
	token string,
	response *dto.TokenValidationResponse) error {

	if !c.cfg.Enabled {
		return nil
	}

	key := tokenValidationPrefix + token
	data, err := json.Marshal(response)

	if err != nil {
		return fmt.Errorf("failed to marshal token validation: %w", err)
	}

	if err := c.client.Set(ctx, key, data, c.tokenTTL).Err(); err != nil {
		c.logger.Error("Failed to cache token validation",
			zap.String("userId", response.UserId),
			zap.Error(err))
		return err
	}

	c.logger.Debug("Cached token validation", zap.String("userId", response.UserId))
	return nil
}

// Retrieves a token validation
func (c *RedisCache) GetTokenValidation(ctx context.Context, token string) (*dto.TokenValidationResponse, bool) {
	if !c.cfg.Enabled {
		return nil, false
	}

	key := tokenValidationPrefix + token
	data, err := c.client.Get(ctx, key).Bytes()

	if err != nil {
		if !errors.Is(err, redis.Nil) {
			c.logger.Error("failed to get to token validation", zap.Error(err))
		}
		return nil, false
	}

	var response dto.TokenValidationResponse
	if err := json.Unmarshal(data, &response); err != nil {
		c.logger.Error("Failed to unmarshal token validation", zap.Error(err))
		return nil, false
	}

	c.logger.Debug("Authorization cache hit", zap.String("key", key))
	return &response, true
}

// removes a token validation from cache
func (c *RedisCache) InvalidateTokenValidation(ctx context.Context, token string) error {
	key := tokenValidationPrefix + token
	return c.client.Del(ctx, key).Err()
}

func (c *RedisCache) authzKey(userID, resource, method string) string {
	return fmt.Sprintf("%s%s:%s:%s", authorizationPrefix, userID, resource, method)
}

// permKey generates cache key for permission
// Format: perm:{user_id}:{permission}
func (c *RedisCache) permKey(userID, permission string) string {
	return fmt.Sprintf("%s%s:%s", permissionPrefix, userID, permission)
}

// CacheAuthorization caches an authorization response
func (c *RedisCache) CacheAuthorization(ctx context.Context, userID, resource, method string, response *dto.AuthorizationResponse) error {
	if !c.cfg.Enabled {
		return nil
	}

	key := c.authzKey(userID, resource, method)
	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal authorization: %w", err)
	}

	if err := c.client.Set(ctx, key, data, c.authzTTL).Err(); err != nil {
		c.logger.Error("Failed to cache authorization",
			zap.String("key", key),
			zap.Error(err))
		return err
	}

	c.logger.Debug("Cached authorization", zap.String("key", key))
	return nil
}

// GetAuthorization retrieves a cached authorization response
func (c *RedisCache) GetAuthorization(ctx context.Context, userID, resource, method string) (*dto.AuthorizationResponse, bool) {
	if !c.cfg.Enabled {
		return nil, false
	}

	key := c.authzKey(userID, resource, method)
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			c.logger.Error("Failed to get cached authorization", zap.Error(err))
		}
		return nil, false
	}

	var response dto.AuthorizationResponse
	if err := json.Unmarshal(data, &response); err != nil {
		c.logger.Error("Failed to unmarshal cached authorization", zap.Error(err))
		return nil, false
	}

	c.logger.Debug("Authorization cache hit", zap.String("key", key))
	return &response, true
}

// removes all authorization entries for a user
func (c *RedisCache) InvalidateUserAuthorizations(ctx context.Context, userID string) error {
	pattern := authorizationPrefix + userID + ":*"
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		if err := c.client.Del(ctx, keys...).Err(); err != nil {
			return err
		}
		c.logger.Debug("Invalidated user authorizations",
			zap.String("userId", userID),
			zap.Int("count", len(keys)))
	}

	return nil
}

// CachePermission caches a permission check result
// with "1" (has permission) or "0" (no permission)
func (c *RedisCache) CachePermission(ctx context.Context, userID, permission string, hasPermission bool) error {
	if !c.cfg.Enabled {
		return nil
	}

	key := c.permKey(userID, permission)
	value := "0"
	if hasPermission {
		value = "1"
	}

	// Use authzTTL for permission cache with default 5 minutes
	ttl := time.Duration(c.cfg.AuthzTTL) * time.Second
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	if err := c.client.Set(ctx, key, value, ttl).Err(); err != nil {
		c.logger.Error("Failed to cache permission",
			zap.String("key", key),
			zap.Error(err))
		return err
	}

	c.logger.Debug("Cached permission",
		zap.String("key", key),
		zap.Bool("hasPermission", hasPermission))
	return nil
}

// GetPermission retrieves a cached permission result
// Returns: (hasPermission, found)
func (c *RedisCache) GetPermission(ctx context.Context, userID, permission string) (bool, bool) {
	if !c.cfg.Enabled {
		return false, false
	}

	key := c.permKey(userID, permission)
	value, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			c.logger.Error("Failed to get cached permission", zap.Error(err))
		}
		return false, false
	}

	hasPermission := value == "1"
	c.logger.Debug("Permission cache hit",
		zap.String("key", key),
		zap.Bool("hasPermission", hasPermission))
	return hasPermission, true
}

// InvalidateUserPermissions removes all permission entries for a user
// Pattern: perm:{user_id}:*
func (c *RedisCache) InvalidateUserPermissions(ctx context.Context, userID string) error {
	pattern := permissionPrefix + userID + ":*"
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		if err := c.client.Del(ctx, keys...).Err(); err != nil {
			return err
		}
		c.logger.Info("Invalidated user permissions",
			zap.String("userId", userID),
			zap.Int("count", len(keys)))
	}

	return nil
}

// InvalidateMultiplePatterns invalidates cache for multiple key patterns using pipelining
func (c *RedisCache) InvalidateMultiplePatterns(ctx context.Context, patterns []string) error {
	if len(patterns) == 0 {
		return nil
	}

	pipe := c.client.Pipeline()
	var allKeys []string

	// Collect all keys matching all patterns
	for _, pattern := range patterns {
		keys, err := c.client.Keys(ctx, pattern).Result()
		if err != nil {
			return fmt.Errorf("failed to get keys for pattern %s: %w", pattern, err)
		}
		allKeys = append(allKeys, keys...)
	}

	// Batch delete all keys using pipeline
	if len(allKeys) > 0 {
		// Redis DEL can accept multiple keys, but we batch in chunks of 100 for safety
		for i := 0; i < len(allKeys); i += 100 {
			end := i + 100
			if end > len(allKeys) {
				end = len(allKeys)
			}
			pipe.Del(ctx, allKeys[i:end]...)
		}

		_, err := pipe.Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to execute pipeline: %w", err)
		}

		c.logger.Debug("Batch invalidated cache keys",
			zap.Int("patterns", len(patterns)),
			zap.Int("keys", len(allKeys)))
	}

	return nil
}

// BatchCachePermissions caches multiple permission results using pipelining
func (c *RedisCache) BatchCachePermissions(ctx context.Context, userID string, permissions map[string]bool) error {
	if !c.cfg.Enabled || len(permissions) == 0 {
		return nil
	}

	pipe := c.client.Pipeline()
	ttl := time.Duration(c.cfg.AuthzTTL) * time.Second
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	for permission, hasPermission := range permissions {
		key := c.permKey(userID, permission)
		value := "0"
		if hasPermission {
			value = "1"
		}
		pipe.Set(ctx, key, value, ttl)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to batch cache permissions: %w", err)
	}

	c.logger.Debug("Batch cached permissions",
		zap.String("userId", userID),
		zap.Int("count", len(permissions)))

	return nil
}
