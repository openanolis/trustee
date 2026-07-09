package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/config"
)

// CORS returns a middleware that handles Cross-Origin Resource Sharing.
//
// It sets the appropriate Access-Control-* response headers for cross-origin
// requests and short-circuits browser preflight (OPTIONS) requests with a
// 204 response. Registered globally, it also runs for routes that only expose
// non-OPTIONS methods, so preflight requests no longer fall through to the
// gin NoRoute handler and return 404.
func CORS(cfg config.CORSConfig) gin.HandlerFunc {
	allowedMethods := strings.Join(cfg.AllowedMethods, ", ")
	allowedHeaders := strings.Join(cfg.AllowedHeaders, ", ")
	maxAge := strconv.Itoa(cfg.MaxAge)

	allowAllOrigins := false
	originSet := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			allowAllOrigins = true
		}
		originSet[o] = struct{}{}
	}

	// Reflect the requested headers only when the configuration allows any header.
	reflectHeaders := len(cfg.AllowedHeaders) == 1 && cfg.AllowedHeaders[0] == "*"

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			switch {
			case allowAllOrigins && !cfg.AllowCredentials:
				c.Header("Access-Control-Allow-Origin", "*")
			case allowAllOrigins:
				// "*" cannot be combined with credentials, so reflect the origin.
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			default:
				if _, ok := originSet[origin]; ok {
					c.Header("Access-Control-Allow-Origin", origin)
					c.Header("Vary", "Origin")
				}
			}

			c.Header("Access-Control-Allow-Methods", allowedMethods)

			if reflectHeaders {
				if reqHeaders := c.Request.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
					c.Header("Access-Control-Allow-Headers", reqHeaders)
				} else {
					c.Header("Access-Control-Allow-Headers", "*")
				}
			} else {
				c.Header("Access-Control-Allow-Headers", allowedHeaders)
			}

			if cfg.AllowCredentials {
				c.Header("Access-Control-Allow-Credentials", "true")
			}
			c.Header("Access-Control-Max-Age", maxAge)
		}

		// Short-circuit preflight requests.
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
