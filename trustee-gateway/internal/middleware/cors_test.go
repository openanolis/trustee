package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/stretchr/testify/assert"
)

func defaultCORSConfig() config.CORSConfig {
	return config.CORSConfig{
		Enabled:          true,
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
		MaxAge:           86400,
	}
}

func newCORSRouter(cfg config.CORSConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(CORS(cfg))
	// Only a POST handler is registered, mirroring the real routes that do not
	// expose an explicit OPTIONS method.
	router.POST("/api/as/challenge", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return router
}

// TestCORSPreflightReturns204 ensures a preflight OPTIONS request to a route
// that only registers non-OPTIONS methods is answered with 204 and the proper
// CORS headers, instead of falling through to gin's 404 NoRoute handler.
func TestCORSPreflightReturns204(t *testing.T) {
	router := newCORSRouter(defaultCORSConfig())

	req := httptest.NewRequest(http.MethodOptions, "/api/as/challenge", nil)
	req.Header.Set("Origin", "http://127.0.0.1:8083")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
	assert.Equal(t, "content-type", w.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "86400", w.Header().Get("Access-Control-Max-Age"))
}

// TestCORSActualRequestPassesThrough ensures non-preflight requests still reach
// their handler and carry the Allow-Origin header.
func TestCORSActualRequestPassesThrough(t *testing.T) {
	router := newCORSRouter(defaultCORSConfig())

	req := httptest.NewRequest(http.MethodPost, "/api/as/challenge", nil)
	req.Header.Set("Origin", "http://127.0.0.1:8083")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
}

// TestCORSAllowCredentialsReflectsOrigin ensures that when credentials are
// allowed the concrete origin is reflected (since "*" is invalid with
// credentials) and the credentials header is set.
func TestCORSAllowCredentialsReflectsOrigin(t *testing.T) {
	cfg := defaultCORSConfig()
	cfg.AllowCredentials = true
	router := newCORSRouter(cfg)

	req := httptest.NewRequest(http.MethodOptions, "/api/as/challenge", nil)
	req.Header.Set("Origin", "http://127.0.0.1:8083")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://127.0.0.1:8083", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "Origin", w.Header().Get("Vary"))
}

// TestCORSSpecificOriginRejectsUnlisted ensures that when explicit origins are
// configured, an unlisted origin does not receive an Allow-Origin header.
func TestCORSSpecificOriginRejectsUnlisted(t *testing.T) {
	cfg := defaultCORSConfig()
	cfg.AllowedOrigins = []string{"http://allowed.example"}
	router := newCORSRouter(cfg)

	req := httptest.NewRequest(http.MethodOptions, "/api/as/challenge", nil)
	req.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Preflight is still short-circuited, but no origin is granted.
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}
