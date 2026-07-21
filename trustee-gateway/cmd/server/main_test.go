package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/openanolis/trustee/gateway/internal/handlers"
	"github.com/openanolis/trustee/gateway/internal/models"
	"github.com/openanolis/trustee/gateway/internal/persistence/repository"
	"github.com/openanolis/trustee/gateway/internal/persistence/storage"
	"github.com/openanolis/trustee/gateway/internal/proxy"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type forwardedRequest struct {
	method        string
	path          string
	body          string
	authorization string
	cookie        string
}

func TestKBSResourceRoutesForwardCompleteAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	forwarded := make(chan forwardedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream request body: %v", err)
			return
		}
		forwarded <- forwardedRequest{
			method:        r.Method,
			path:          r.URL.Path,
			body:          string(body),
			authorization: r.Header.Get("Authorization"),
			cookie:        r.Header.Get("Cookie"),
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Coverage", "complete")
		http.SetCookie(w, &http.Cookie{Name: "kbs-session-id", Value: "returned-session"})
		if r.URL.Path == "/kbs/v0/resources" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = fmt.Fprintf(w, `{"forwarded":%q}`, r.Method+" "+r.URL.Path)
	}))
	defer upstream.Close()

	p, err := proxy.NewProxy(&config.Config{
		KBS:                config.ServiceConfig{URL: upstream.URL},
		AttestationService: config.ServiceConfig{URL: upstream.URL},
	})
	require.NoError(t, err)

	db, err := gorm.Open(sqlite.Open("file:kbs_resource_routes?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AttestationRecord{}, &models.ResourceRequest{}))
	auditRepo := repository.NewAuditRepository(&storage.Database{DB: db})

	router := gin.New()
	setupKBSRoutes(router, handlers.NewKBSHandler(p, auditRepo))

	tests := []struct {
		name          string
		method        string
		gatewayPath   string
		upstreamPath  string
		body          string
		copiesCookies bool
	}{
		{name: "public key", method: http.MethodGet, gatewayPath: "/api/kbs/v0/resource/pubkey", upstreamPath: "/kbs/v0/resource/pubkey", copiesCookies: true},
		{name: "reload keys", method: http.MethodPost, gatewayPath: "/api/kbs/v0/resource/reload", upstreamPath: "/kbs/v0/resource/reload", body: `{}`, copiesCookies: true},
		{name: "rewrap resources", method: http.MethodPost, gatewayPath: "/api/kbs/v0/resource/rewrap", upstreamPath: "/kbs/v0/resource/rewrap", body: `{}`, copiesCookies: true},
		{name: "rotate keys", method: http.MethodPost, gatewayPath: "/api/kbs/v0/resource/rotate", upstreamPath: "/kbs/v0/resource/rotate", body: `{}`, copiesCookies: true},
		{name: "get resource", method: http.MethodGet, gatewayPath: "/api/kbs/v0/resource/repo/secret/tag", upstreamPath: "/kbs/v0/resource/repo/secret/tag", copiesCookies: true},
		{name: "set resource", method: http.MethodPost, gatewayPath: "/api/kbs/v0/resource/repo/secret/tag", upstreamPath: "/kbs/v0/resource/repo/secret/tag", body: `encrypted-envelope`},
		{name: "delete resource", method: http.MethodDelete, gatewayPath: "/api/kbs/v0/resource/repo/secret/tag", upstreamPath: "/kbs/v0/resource/repo/secret/tag"},
		{name: "list resources", method: http.MethodGet, gatewayPath: "/api/kbs/v0/resources", upstreamPath: "/kbs/v0/resources"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.gatewayPath, bytes.NewBufferString(tc.body))
			req.Header.Set("Authorization", "Bearer admin-token")
			req.AddCookie(&http.Cookie{Name: "kbs-session-id", Value: "request-session"})
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, req)
			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			require.Equal(t, "complete", recorder.Header().Get("X-Upstream-Coverage"))

			select {
			case got := <-forwarded:
				require.Equal(t, tc.method, got.method)
				require.Equal(t, tc.upstreamPath, got.path)
				require.Equal(t, tc.body, got.body)
				require.Equal(t, "Bearer admin-token", got.authorization)
				require.Equal(t, "kbs-session-id=request-session", got.cookie)
			case <-time.After(time.Second):
				t.Fatal("request was not forwarded to KBS")
			}

			if tc.copiesCookies {
				cookies := recorder.Result().Cookies()
				require.Len(t, cookies, 1)
				require.Equal(t, "kbs-session-id", cookies[0].Name)
				require.Equal(t, "returned-session", cookies[0].Value)
			}
		})
	}
}
