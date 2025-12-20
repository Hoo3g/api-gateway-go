package proxy

import (
	"api-gateway-go/internal/config"
	"api-gateway-go/internal/dto"
	"api-gateway-go/internal/middleware"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type ReverseProxy struct {
	cfg    *config.Config
	logger *zap.Logger
}

func NewReverseProxy(cfg *config.Config, logger *zap.Logger) *ReverseProxy {
	return &ReverseProxy{
		cfg:    cfg,
		logger: logger,
	}
}

func (p *ReverseProxy) createProxy(target *url.URL, serviceName string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host

		p.logger.Debug("Proxying request",
			zap.String("service", serviceName),
			zap.String("method", req.Method),
			zap.String("path", req.URL.Path),
			zap.String("target", target.String()))
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		p.logger.Error("Proxy error",
			zap.String("service", serviceName),
			zap.String("path", r.URL.Path),
			zap.Error(err))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"status":502,"message":"Service unavailable"}`))
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("X-Gateway", "tutor-platform")
		resp.Header.Set("X-Service", serviceName)
		return nil
	}

	return proxy
}

func (p *ReverseProxy) ProxyTo(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		serviceURL := p.cfg.GetServiceURL(serviceName)
		if serviceURL == "" {
			p.logger.Error("Unknown service", zap.String("service", serviceName))
			c.JSON(http.StatusBadGateway, dto.ErrorResponse{
				Status:    http.StatusBadGateway,
				Message:   "Service not found",
				Path:      c.Request.URL.Path,
				Timestamp: time.Now().Unix(),
			})
			return
		}

		target, err := url.Parse(serviceURL)
		if err != nil {
			p.logger.Error("Invalid service URL",
				zap.String("service", serviceName),
				zap.String("url", serviceURL),
				zap.Error(err))
			c.JSON(http.StatusBadGateway, dto.ErrorResponse{
				Status:    http.StatusBadGateway,
				Message:   "Invalid service configuration",
				Path:      c.Request.URL.Path,
				Timestamp: time.Now().Unix(),
			})
			return
		}

		proxy := p.createProxy(target, serviceName)
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

func (p *ReverseProxy) StreamProxy(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		serviceURL := p.cfg.GetServiceURL(serviceName)
		if serviceURL == "" {
			c.JSON(http.StatusBadGateway, dto.ErrorResponse{
				Status:    http.StatusBadGateway,
				Message:   "Service not found",
				Path:      c.Request.URL.Path,
				Timestamp: time.Now().Unix(),
			})
			return
		}

		target, err := url.Parse(serviceURL + c.Request.URL.Path)
		if err != nil {
			c.JSON(http.StatusBadGateway, dto.ErrorResponse{
				Status:    http.StatusBadGateway,
				Message:   "Invalid service URL",
				Path:      c.Request.URL.Path,
				Timestamp: time.Now().Unix(),
			})
			return
		}

		target.RawQuery = c.Request.URL.RawQuery
		//create request
		req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target.String(), c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
				Status:    http.StatusInternalServerError,
				Message:   "Failed to create request",
				Path:      c.Request.URL.Path,
				Timestamp: time.Now().Unix(),
			})
			return
		}

		// Copy headers
		for key, values := range c.Request.Header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		p.copyHeaders(req, c)

		// Make request with timeout
		timeout := p.cfg.GetServiceTimeout(serviceName)
		client := &http.Client{Timeout: timeout}

		resp, err := client.Do(req)
		if err != nil {
			p.logger.Error("Stream proxy error",
				zap.String("service", serviceName),
				zap.Error(err))
			c.JSON(http.StatusBadGateway, dto.ErrorResponse{
				Status:    http.StatusBadGateway,
				Message:   "Service unavailable",
				Path:      c.Request.URL.Path,
				Timestamp: time.Now().Unix(),
			})
			return
		}
		defer resp.Body.Close()

		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				c.Header(key, value)
			}
		}

		c.Status(resp.StatusCode)

		// Stream response body
		io.Copy(c.Writer, resp.Body)
	}
}

func (p *ReverseProxy) copyHeaders(req *http.Request, c *gin.Context) {
	// Copy user info headers if present
	if userInfo, exists := middleware.GetUserInfo(c); exists {
		req.Header.Set("X-User-Id", userInfo.UserID)
		req.Header.Set("X-Username", userInfo.Username)
		req.Header.Set("X-User-Email", userInfo.Email)
		req.Header.Set("X-User-Roles", strings.Join(userInfo.Roles, ","))
	}

	// Copy request ID
	if requestID, exists := c.Get(middleware.RequestIdKey); exists {
		req.Header.Set("X-Request-ID", requestID.(string))
	}

	// Copy correlation headers
	if traceID := c.GetHeader("X-Trace-ID"); traceID != "" {
		req.Header.Set("X-Trace-ID", traceID)
	}
}
