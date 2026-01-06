package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/config"
)

func TestProxy_ForwardRequest(t *testing.T) {
	// Create a test HTTP server for KBS
	kbsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Error("X-Forwarded-For header not set")
		}

		// Read request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read request body: %v", err)
		}

		// Check if request body was forwarded correctly
		if string(body) != "test request body" {
			t.Errorf("Request body not forwarded correctly, got: %s", string(body))
		}

		// Verify cookies are not duplicated when proxy forwards requests.
		// The proxy copies headers and also adds cookies; it must not do both for Cookie header.
		cookies := r.Cookies()
		if len(cookies) != 1 || cookies[0].Name != "kbs-session-id" || cookies[0].Value != "test-session-id" {
			t.Fatalf("expected exactly one kbs-session-id cookie, got: %#v (raw Cookie header=%q)", cookies, r.Header.Get("Cookie"))
		}

		// Set a cookie back to the client
		http.SetCookie(w, &http.Cookie{
			Name:  "kbs-session-id",
			Value: "test-session-id",
		})

		// Write response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer kbsServer.Close()

	// Create test config
	cfg := &config.Config{
		KBS: config.ServiceConfig{
			URL: kbsServer.URL,
		},
	}

	// Create proxy
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Create a test request
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest("POST", "/test", bytes.NewBufferString("test request body"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "kbs-session-id", Value: "test-session-id"})
	c.Request = req

	// Forward the request
	resp, err := proxy.ForwardToKBS(c)
	if err != nil {
		t.Fatalf("Failed to forward request: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check if cookie was received
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "kbs-session-id" || cookies[0].Value != "test-session-id" {
		t.Errorf("Expected kbs-session-id cookie, got %v", cookies)
	}

	// Check response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(respBody) != `{"status": "ok"}` {
		t.Errorf("Unexpected response body: %s", string(respBody))
	}
}
