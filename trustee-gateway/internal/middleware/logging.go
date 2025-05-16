package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Logger returns a middleware that logs requests
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Log request details
		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		logrus.WithFields(logrus.Fields{
			"client_ip":  clientIP,
			"duration":   latency,
			"method":     method,
			"path":       path,
			"status":     statusCode,
			"user_agent": c.Request.UserAgent(),
			"referer":    c.Request.Referer(),
		}).Info("Request processed")
	}
}
