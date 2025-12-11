package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server         ServerConfig         `mapstructure:"server"`
	CORS           CORSConfig           `mapstructure:"cors"`
	Redis          RedisConfig          `mapstructure:"redis"`
	Cache          CacheConfig          `mapstructure:"cache"`
	RateLimit      RateLimitConfig      `mapstructure:"rateLimit"`
	CircuitBreaker CircuitBreakerConfig `mapstructure:"circuitBreaker"`
	Services       ServicesConfig       `mapstructure:"services"`
	Logging        LoggingConfig        `mapstructure:"logging"`
	Metrics        MetricsConfig        `mapstructure:"metrics"`
}

type ServerConfig struct {
	Port           int           `mapstructure:"port"`
	ReadTimeout    time.Duration `mapstructure:"readTimeout"`
	WriteTimeout   time.Duration `mapstructure:"writeTimeout"`
	MaxHeaderBytes int           `mapstructure:"maxHeaderBytes"`
}

type CORSConfig struct {
	AllowedOrigins   []string `mapstructure:"allowedOrigins"`
	AllowedMethods   []string `mapstructure:"allowedMethods"`
	AllowedHeaders   []string `mapstructure:"allowedHeaders"`
	AllowCredentials bool     `mapstructure:"allowCredentials"`
	MaxAge           int      `mapstructure:"maxAge"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	PoolSize int    `mapstructure:"poolSize"`
}

func (r RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

type CacheConfig struct {
	Enabled  bool `mapstructure:"enabled"`
	TokenTTL int  `mapstructure:"tokenTTL"`
	AuthzTTL int  `mapstructure:"authzTTL"`
}

type RateLimitConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	DefaultLimit  int  `mapstructure:"defaultLimit"`
	WindowSeconds int  `mapstructure:"windowSeconds"`
}

type CircuitBreakerConfig struct {
	Enabled          bool          `mapstructure:"enabled"`
	Threshold        int           `mapstructure:"threshold"`
	Timeout          time.Duration `mapstructure:"timeout"`
	HalfOpenRequests int           `mapstructure:"halfOpenRequests"`
}

type ServiceConfig struct {
	URL              string        `mapstructure:"url"`
	Timeout          time.Duration `mapstructure:"timeout"`
	ValidateEndpoint string        `mapstructure:"validateEndpoint"`
	CheckEndpoint    string        `mapstructure:"checkEndpoint"`
}

type ServicesConfig struct {
	Authentication ServiceConfig `mapstructure:"authentication"`
	Authorization  ServiceConfig `mapstructure:"authorization"`
	User           ServiceConfig `mapstructure:"user"`
	Order          ServiceConfig `mapstructure:"order"`
	Payment        ServiceConfig `mapstructure:"payment"`
	Payout         ServiceConfig `mapstructure:"payout"`
	Notification   ServiceConfig `mapstructure:"notification"`
	Storage        ServiceConfig `mapstructure:"storage"`
	Analytics      ServiceConfig `mapstructure:"analytics"`
	Classroom      ServiceConfig `mapstructure:"classroom"`
	Content        ServiceConfig `mapstructure:"content"`
	Quiz           ServiceConfig `mapstructure:"quiz"`
	Enrollment     ServiceConfig `mapstructure:"enrollment"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set default
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.readTimeout", "30s")
	v.SetDefault("server.writeTimeout", "30s")
	v.SetDefault("server.maxHeaderBytes", 1048576)

	v.SetDefault("cache.enabled", true)
	v.SetDefault("cache.tokenTTL", 300)
	v.SetDefault("cache.authzTTL", 60)

	v.SetDefault("rateLimit.enabled", true)
	v.SetDefault("rateLimit.defaultLimit", 100)
	v.SetDefault("rateLimit.windowSeconds", 60)

	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")

	// read config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("./config")
		v.AddConfigPath(".")
	}

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Override with environment variables
	v.SetEnvPrefix("GATEWAY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return &cfg, nil
}

func (c *Config) GetServiceURL(serviceName string) string {
	switch serviceName {
	case "authorization":
		return c.Services.Authorization.URL
	case "authentication":
		return c.Services.Authentication.URL
	case "user":
		return c.Services.User.URL
	case "order":
		return c.Services.Order.URL
	case "payment":
		return c.Services.Payment.URL
	case "payout":
		return c.Services.Payout.URL
	case "notification":
		return c.Services.Notification.URL
	case "storage":
		return c.Services.Storage.URL
	case "analytics":
		return c.Services.Analytics.URL
	case "classroom":
		return c.Services.Classroom.URL
	case "content":
		return c.Services.Content.URL
	case "quiz":
		return c.Services.Quiz.URL
	case "enrollment":
		return c.Services.Enrollment.URL
	default:
		return ""
	}
}

func (c *Config) GetServiceTimeout(serviceName string) time.Duration {
	switch serviceName {
	case "authentication":
		return c.Services.Authentication.Timeout
	case "authorization":
		return c.Services.Authorization.Timeout
	case "user":
		return c.Services.User.Timeout
	case "order":
		return c.Services.Order.Timeout
	case "payment":
		return c.Services.Payment.Timeout
	case "payout":
		return c.Services.Payout.Timeout
	case "notification":
		return c.Services.Notification.Timeout
	case "storage":
		return c.Services.Storage.Timeout
	case "analytics":
		return c.Services.Analytics.Timeout
	case "classroom":
		return c.Services.Classroom.Timeout
	case "content":
		return c.Services.Content.Timeout
	case "quiz":
		return c.Services.Quiz.Timeout
	case "enrollment":
		return c.Services.Enrollment.Timeout
	default:
		return 10 * time.Second
	}
}
