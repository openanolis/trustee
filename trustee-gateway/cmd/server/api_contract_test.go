package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/openanolis/trustee/gateway/internal/handlers"
	"github.com/stretchr/testify/require"
)

type contractRoute struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// Every registered route needs a documented E2E contract entry. The E2E suite
// separately requires a successful real-service call for every contract entry.
func TestGatewayRoutesMatchDocumentedE2EContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "e2e", "api-contract.json"))
	require.NoError(t, err)
	var routes []contractRoute
	require.NoError(t, json.Unmarshal(data, &routes))
	doc, err := os.ReadFile(filepath.Join("..", "..", "trustee_gateway_api.md"))
	require.NoError(t, err)
	contract := map[contractRoute]bool{}
	for _, route := range routes {
		require.False(t, contract[route], "duplicate API contract entry: %+v", route)
		contract[route] = true
		segments := strings.Split(route.Path, "/")
		for i, segment := range segments {
			if strings.HasPrefix(segment, ":") {
				segments[i] = "{" + segment[1:] + "}"
			}
		}
		require.Contains(t, string(doc), "`"+route.Method+" "+strings.Join(segments, "/")+"`", "document E2E-covered API %+v", route)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	setupRoutes(router, handlers.NewKBSHandler(nil, nil), handlers.NewRVPSHandler(nil, nil),
		handlers.NewAttestationServiceHandler(nil, nil), handlers.NewAuditHandler(nil),
		handlers.NewHealthCheckHandler(nil, nil), nil,
		handlers.NewAAInstanceHandler(nil, &config.AttestationAgentInstanceInfoConfig{}),
		handlers.NewCredentialHandler(&config.CredentialConfig{}))
	registered := map[contractRoute]bool{}
	for _, route := range router.Routes() {
		if route.Path == "/api/rvps/*path" {
			continue
		}
		entry := contractRoute{route.Method, route.Path}
		require.True(t, contract[entry], "new Gateway route needs documentation and E2E coverage: %+v", entry)
		registered[entry] = true
	}
	// RVPS has a wildcard Gateway route, so derive its logical operations from
	// KBS's actual dispatch branches rather than silently treating ANY as coverage.
	backend, err := os.ReadFile(filepath.Join("..", "..", "..", "kbs", "src", "api_server.rs"))
	require.NoError(t, err)
	dispatch := regexp.MustCompile(`"rvps"\s*if request\.method\(\) == Method::([A-Z]+)\s*&&\s*additional_path\s*(?:==\s*"([^"]+)"|\.starts_with\("([^"]+)"\))`)
	matches := dispatch.FindAllStringSubmatch(string(backend), -1)
	require.NotEmpty(t, matches, "RVPS dispatch parsing changed; update the route coverage guard")
	for _, match := range matches {
		path := match[2]
		if path == "" {
			path = match[3] + ":name"
		}
		entry := contractRoute{match[1], "/api/rvps" + path}
		require.True(t, contract[entry], "new RVPS operation needs documentation and E2E: %+v", entry)
		registered[entry] = true
	}
	for route := range contract {
		require.True(t, registered[route], "documented E2E API has no route: %+v", route)
	}
}
