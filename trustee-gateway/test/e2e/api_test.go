//go:build e2e

// Copyright (c) 2026 Alibaba. SPDX-License-Identifier: Apache-2.0
package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const allowPolicy = "package policy\ndefault allow = true\n"
const denyPolicy = "package policy\ndefault allow = false\n"
const resourcePath = "/api/kbs/v0/resource/e2e/secret/item.v1"

func TestGatewayAPI(t *testing.T) {
	allCoverage := map[apiRoute]int{}
	cases := []struct {
		name, backend string
		shared        bool
	}{
		{"local-fs", "LocalFs", false},
		{"encrypted-local-fs", "EncryptedLocalFs", false},
		{"encrypted-db-sqlite", "EncryptedDb", false},
		{"shared-store", "SharedStore", true},
		{"encrypted-db-mysql", "EncryptedDb", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStack(t, tc.name, tc.backend, tc.shared)
			s.exercise()
			for route, count := range s.coverage {
				allCoverage[route] += count
			}
		})
	}
	if t.Failed() {
		return
	}
	for _, route := range contract(t) {
		require.Positive(t, allCoverage[route], "missing successful E2E call: %s %s", route.Method, route.Path)
	}
	if dir := os.Getenv("TRUSTEE_E2E_ARTIFACT_DIR"); dir != "" {
		require.NoError(t, os.MkdirAll(dir, 0700))
		type result struct {
			apiRoute
			SuccessfulCalls int `json:"successful_calls"`
		}
		results := []result{}
		for _, route := range contract(t) {
			results = append(results, result{route, allCoverage[route]})
		}
		writeJSON(t, filepath.Join(dir, "api-coverage.json"), results)
	}
	t.Logf("all %d Gateway API operations exercised successfully against real services", len(contract(t)))
}

func (s *stack) setResourcePolicy(replica int, policy string) {
	s.request(replica, http.MethodPost, "/api/kbs/v0/resource-policy", map[string]any{"policy": b64([]byte(policy))}, s.adminHeaders(), 200)
}

func (s *stack) register(replica int, values any) {
	message := map[string]any{"version": "0.1.0", "type": "sample", "payload": base64.StdEncoding.EncodeToString(jsonBytes(s.t, values))}
	s.request(replica, http.MethodPost, "/api/rvps/register", map[string]any{"message": string(jsonBytes(s.t, message))}, s.adminHeaders(), 200)
}

func (s *stack) exercise() {
	t := s.t
	t.Log("health, CORS, credentials, AA heartbeat and cross-replica listing")
	data, _ := s.request(0, "GET", "/api/health", nil, nil, 200)
	require.Equal(t, "ok", object(t, data)["status"])
	data, _ = s.request(1, "GET", "/api/services-health", nil, nil, 200)
	for _, service := range []string{"gateway", "kbs", "as", "rvps"} {
		require.Equal(t, "ok", object(t, data)[service].(map[string]any)["status"], "%s health", service)
	}
	_, headers := s.request(0, "OPTIONS", "/api/kbs/v0/resource/rotate", nil, map[string]string{"Origin": "http://localhost", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Authorization,Content-Type"}, 204)
	require.NotEmpty(t, headers.Get("Access-Control-Allow-Origin"))
	data, _ = s.request(0, "GET", "/api/credential", nil, nil, 200)
	require.True(t, bytes.Equal(data, []byte("synthetic-e2e-credential")))
	credential := filepath.Join(s.dir, "credential")
	require.NoError(t, os.Rename(credential, credential+".saved"))
	s.request(1, "GET", "/api/credential", nil, nil, 404)
	require.NoError(t, os.Rename(credential+".saved", credential))
	s.request(0, "POST", "/api/aa-instance/heartbeat", nil, nil, 400)
	s.request(0, "POST", "/api/aa-instance/heartbeat", nil, map[string]string{"AAInstanceInfo": "{"}, 400)
	s.request(0, "POST", "/api/aa-instance/heartbeat", nil, map[string]string{"AAInstanceInfo": `{"image_id":"e2e"}`}, 400)
	instance := map[string]string{"AAInstanceInfo": `{"instance_id":"e2e-instance","instance_name":"api-e2e","ip":"127.0.0.2"}`}
	s.request(0, "POST", "/api/aa-instance/heartbeat", nil, instance, 200)
	s.request(1, "POST", "/api/aa-instance/heartbeat", nil, instance, 200)
	data, _ = s.request(1, "GET", "/api/aa-instance/list", nil, nil, 200)
	require.Equal(t, float64(1), object(t, data)["count"])
	require.Equal(t, "e2e-instance", object(t, data)["active_aa_instances"].([]any)[0].(map[string]any)["instance_id"])

	t.Log("management authentication, policy CRUD through KBS and both AS aliases")
	for _, route := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/kbs/v0/attestation-policy", map[string]any{"policy_id": "unauthorized", "policy": b64([]byte(allowPolicy))}},
		{"GET", "/api/kbs/v0/attestation-policy/default", nil},
		{"GET", "/api/kbs/v0/attestation-policies", nil},
		{"DELETE", "/api/kbs/v0/attestation-policy/default", nil},
		{"GET", "/api/kbs/v0/resources", nil},
		{"POST", "/api/kbs/v0/resource-policy", b64([]byte(allowPolicy))},
		{"GET", "/api/kbs/v0/resource-policy", nil},
		{"POST", resourcePath, "unauthorized"}, {"DELETE", resourcePath, nil},
		{"GET", "/api/kbs/v0/resource/pubkey", nil}, {"POST", "/api/kbs/v0/resource/reload", nil},
		{"POST", "/api/kbs/v0/resource/rewrap", nil}, {"POST", "/api/kbs/v0/resource/rotate", nil},
		{"GET", "/api/rvps/query", nil}, {"POST", "/api/rvps/register", map[string]any{"message": "invalid"}},
		{"POST", "/api/rvps/set_reference_value_list", map[string]any{"rv_list": []any{}}}, {"DELETE", "/api/rvps/delete/unknown", nil},
	} {
		s.request(0, route.method, route.path, route.body, nil, 401)
		s.request(1, route.method, route.path, route.body, map[string]string{"Authorization": "Bearer invalid"}, 401)
	}
	s.setResourcePolicy(0, allowPolicy)
	data, _ = s.request(1, "GET", "/api/kbs/v0/resource-policy", nil, s.adminHeaders(), 200)
	require.Equal(t, b64([]byte(allowPolicy)), string(data))
	for i, prefix := range []string{"/api/as", "/api/attestation-service"} {
		id := fmt.Sprintf("e2e_policy_%d", i)
		payload := map[string]any{"policy_id": id, "policy": b64([]byte(allowPolicy))}
		s.request(0, "POST", prefix+"/policy", payload, nil, 200)
		data, _ = s.request(1, "GET", prefix+"/policy/"+id, nil, nil, 200)
		require.Equal(t, b64([]byte(allowPolicy)), string(data))
		data, _ = s.request(1, "GET", prefix+"/policies", nil, nil, 200)
		require.Contains(t, string(data), id)
		data, _ = s.request(1, "GET", "/api/kbs/v0/attestation-policy/"+id, nil, s.adminHeaders(), 200)
		require.Equal(t, b64([]byte(allowPolicy)), string(data))
		s.request(1, "POST", "/api/kbs/v0/attestation-policy", map[string]any{"policy_id": id, "policy": b64([]byte(denyPolicy))}, s.adminHeaders(), 200)
		data, _ = s.request(0, "GET", prefix+"/policy/"+id, nil, nil, 200)
		require.Equal(t, b64([]byte(denyPolicy)), string(data))
		s.request(1, "DELETE", prefix+"/policy/"+id, nil, nil, 200)
		data, _ = s.request(0, "GET", prefix+"/policies", nil, nil, 200)
		require.NotContains(t, string(data), id)
	}
	s.request(0, "POST", "/api/kbs/v0/attestation-policy", map[string]any{"policy_id": "delete_via_kbs", "policy": b64([]byte(allowPolicy))}, s.adminHeaders(), 200)
	data, _ = s.request(1, "GET", "/api/kbs/v0/attestation-policies", nil, s.adminHeaders(), 200)
	require.Contains(t, object(t, data), "delete_via_kbs")
	s.request(1, "DELETE", "/api/kbs/v0/attestation-policy/delete_via_kbs", nil, s.adminHeaders(), 200)
	data, _ = s.request(0, "GET", "/api/kbs/v0/attestation-policies", nil, s.adminHeaders(), 200)
	require.NotContains(t, object(t, data), "delete_via_kbs")

	s.testAS()
	s.testReferences()

	t.Log("RCAR auth -> attestation -> independently verified JWT -> decrypted resource")
	teePrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cookie, token := s.attest(teePrivate)
	var publicKey []byte
	encrypted := s.backend == "EncryptedDb" || s.backend == "EncryptedLocalFs"
	plain := []byte("resource payload: gateway E2E")
	upload := plain
	if encrypted {
		publicKey, _ = s.request(0, "GET", "/api/kbs/v0/resource/pubkey", nil, s.adminHeaders(), 200)
		upload = envelope(t, publicKey, plain)
	} else {
		for _, operation := range []string{"pubkey", "reload", "rewrap", "rotate"} {
			method := "POST"
			if operation == "pubkey" {
				method = "GET"
			}
			s.request(0, method, "/api/kbs/v0/resource/"+operation, nil, s.adminHeaders(), 500)
		}
	}
	s.request(0, "POST", resourcePath, upload, s.adminHeaders(), 200)
	resourceHeaders := map[string]string{"Cookie": cookie, "AAInstanceInfo": instance["AAInstanceInfo"]}
	s.request(0, "GET", resourcePath, nil, nil, 401)
	s.request(0, "GET", resourcePath, nil, map[string]string{"Authorization": "Bearer " + s.admin}, 401)
	s.readResource(1, resourcePath, resourceHeaders, teePrivate, plain)
	updated := []byte("updated resource payload")
	updatedUpload := updated
	if encrypted {
		updatedUpload = envelope(t, publicKey, updated)
	}
	s.request(1, "POST", resourcePath, updatedUpload, s.adminHeaders(), 200)
	s.readResource(0, resourcePath, resourceHeaders, teePrivate, updated)
	s.request(0, "POST", resourcePath, upload, s.adminHeaders(), 200)
	s.readResource(1, resourcePath, resourceHeaders, teePrivate, plain)
	// Authorization with a signed attestation JWT, independently of cookies.
	s.readResource(0, resourcePath, map[string]string{"Authorization": "Bearer " + token}, teePrivate, plain)
	parts := strings.Split(token, ".")
	parts[2] = b64(make([]byte, 256))
	s.request(1, "GET", resourcePath, nil, map[string]string{"Authorization": "Bearer " + strings.Join(parts, ".")}, 401)
	data, _ = s.request(1, "GET", "/api/kbs/v0/resources", nil, s.adminHeaders(), 200)
	require.Contains(t, string(data), "item.v1")
	// Percent-escaped path must identify the same stored resource, not a new key.
	s.readResource(1, strings.ReplaceAll(resourcePath, "item.v1", "item%2Ev1"), resourceHeaders, teePrivate, plain)
	s.setResourcePolicy(1, denyPolicy)
	s.request(0, "GET", resourcePath, nil, resourceHeaders, 403)
	s.setResourcePolicy(0, allowPolicy)
	s.readResource(1, resourcePath, resourceHeaders, teePrivate, plain)
	if s.shared {
		s.testConcurrentWrites(upload)
	}
	if encrypted {
		s.testRotation(teePrivate, resourceHeaders, plain, publicKey)
	}

	t.Log("restart persistence: resources, policies, RVPS values, heartbeat and audit")
	// Warm audit reads before shutdown; asynchronous writes must have completed.
	s.auditChecks(instance["AAInstanceInfo"])
	s.restartReplica(1)
	s.readResource(1, resourcePath, map[string]string{"Authorization": "Bearer " + token}, teePrivate, plain)
	data, _ = s.request(1, "GET", "/api/kbs/v0/resource-policy", nil, s.adminHeaders(), 200)
	require.Equal(t, b64([]byte(allowPolicy)), string(data))
	data, _ = s.request(1, "GET", "/api/rvps/query", nil, s.adminHeaders(), 200)
	require.Contains(t, object(t, data), "persistent.value")
	data, _ = s.request(1, "GET", "/api/aa-instance/list", nil, nil, 200)
	require.Equal(t, float64(1), object(t, data)["count"])
	s.auditChecks(instance["AAInstanceInfo"])
	s.request(1, "DELETE", resourcePath, nil, s.adminHeaders(), 200)
	eventually(t, "DELETE request audited", func() bool {
		data, _ := s.request(0, "GET", "/api/audit/resources?repository=e2e&tag=item.v1&method=DELETE&successful=true", nil, nil, 200)
		return object(t, data)["total"].(float64) >= 1
	})
	data, _ = s.request(0, "GET", "/api/kbs/v0/resources", nil, s.adminHeaders(), 200)
	require.NotContains(t, string(data), "item.v1")
	// Backend currently reports a missing stored resource as PluginInternalError.
	s.request(0, "GET", resourcePath, nil, map[string]string{"Authorization": "Bearer " + token}, 500)
	s.testOIDC()
}

func (s *stack) attest(key *rsa.PrivateKey) (string, string) {
	t := s.t
	s.request(0, "POST", "/api/kbs/v0/auth", map[string]any{"version": "0.0.0", "tee": "sample", "extra-params": ""}, nil, 502)
	data, headers := s.request(0, "POST", "/api/kbs/v0/auth", map[string]any{"version": "0.4.0", "tee": "sample", "extra-params": ""}, nil, 200)
	challenge := object(t, data)
	cookies := (&http.Response{Header: headers}).Cookies()
	require.NotEmpty(t, cookies)
	cookie := cookies[0].Name + "=" + cookies[0].Value
	require.Equal(t, "kbs-session-id", cookies[0].Name)
	if s.shared {
		s.restartReplica(1)
	} // pending session survives a different replica's restart
	runtime := map[string]any{"nonce": challenge["nonce"], "tee-pubkey": teeKey(t, key)}
	bound := map[string]any{"nonce": challenge["nonce"], "tee-pubkey": teeKey(t, key), "additional-evidence": ""}
	payload := map[string]any{"runtime-data": runtime, "tee-evidence": map[string]any{"primary_evidence": sampleEvidence(t, bound), "additional_evidence": ""}}
	data, _ = s.request(1, "POST", "/api/kbs/v0/attest", payload, map[string]string{"Cookie": cookie, "AAInstanceInfo": `{"instance_id":"e2e-instance"}`}, 200)
	token := object(t, data)["token"].(string)
	claims := verifyToken(t, token, &s.signer.PublicKey)
	require.Equal(t, "trustee-e2e", claims["iss"])
	data, _ = s.request(0, "POST", "/api/kbs/v0/attest", payload, map[string]string{"Cookie": cookie}, 200)
	require.True(t, token == object(t, data)["token"].(string), "attested session retry must return the same token")
	s.request(0, "POST", "/api/kbs/v0/attest", payload, nil, 502)
	// A separate, not-yet-attested session rejects a mismatched nonce.
	_, otherHeaders := s.request(0, "POST", "/api/kbs/v0/auth", map[string]any{"version": "0.4.0", "tee": "sample", "extra-params": ""}, nil, 200)
	otherCookie := (&http.Response{Header: otherHeaders}).Cookies()[0]
	s.request(1, "POST", "/api/kbs/v0/attest", payload, map[string]string{"Cookie": otherCookie.Name + "=" + otherCookie.Value}, 502)
	// Correct session nonce with deliberately wrong report-data must reach and
	// fail the verifier, rather than merely fail session lookup.
	otherData, otherHeaders := s.request(0, "POST", "/api/kbs/v0/auth", map[string]any{"version": "0.4.0", "tee": "sample", "extra-params": ""}, nil, 200)
	otherCookie = (&http.Response{Header: otherHeaders}).Cookies()[0]
	runtime["nonce"] = object(t, otherData)["nonce"]
	badEvidence := map[string]any{"svn": "1", "measure_register": strings.Repeat("0", 64), "report_data": base64.StdEncoding.EncodeToString(make([]byte, 48))}
	badPayload := map[string]any{"runtime-data": runtime, "tee-evidence": map[string]any{"primary_evidence": badEvidence, "additional_evidence": ""}}
	s.request(1, "POST", "/api/kbs/v0/attest", badPayload, map[string]string{"Cookie": otherCookie.Name + "=" + otherCookie.Value}, 502)
	return cookie, token
}

func (s *stack) readResource(replica int, path string, headers map[string]string, key *rsa.PrivateKey, expected []byte) {
	data, _ := s.request(replica, "GET", path, nil, headers, 200)
	require.True(s.t, bytes.Equal(expected, decryptResource(s.t, key, data)), "decrypted resource differs from provisioned plaintext")
}

func (s *stack) testAS() {
	t := s.t
	for _, prefix := range []string{"/api/as", "/api/attestation-service"} {
		supplemental, _ := s.request(0, "POST", prefix+"/challenge", map[string]any{"tee": "sample"}, nil, 200)
		require.Empty(t, supplemental, "sample has no supplemental challenge")
		data, _ := s.request(0, "POST", prefix+"/challenge", map[string]any{}, nil, 200)
		challenge := object(t, data)
		challengeToken := challenge["extra-params"].(map[string]any)["jwt"].(string)
		claims := verifyToken(t, challengeToken, &s.signer.PublicKey)
		require.Equal(t, challenge["nonce"], claims["nonce"])
		runtime := map[string]any{"challenge_token": challengeToken}
		data, _ = s.request(1, "POST", prefix+"/attestation", asEvidence(t, runtime, "default"), map[string]string{"AAInstanceInfo": `{"instance_id":"e2e-instance"}`}, 200)
		verifyToken(t, string(data), &s.signer.PublicKey)
		s.request(1, "POST", prefix+"/attestation", asEvidence(t, map[string]any{"challenge_token": expiredChallenge(t, s.signer)}, "default"), nil, 401)
		s.request(1, "POST", prefix+"/attestation", asEvidence(t, map[string]any{"challenge_token": "invalid"}, "default"), nil, 401)
		s.request(0, "POST", prefix+"/attestation", "{", nil, 400)
		s.request(0, "POST", prefix+"/challenge", map[string]any{"tee": "unknown"}, nil, 400)
		data, _ = s.request(1, "GET", prefix+"/certificate", nil, nil, 200)
		block, _ := pem.Decode(data)
		require.NotNil(t, block)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		require.Equal(t, s.signer.N, cert.PublicKey.(*rsa.PublicKey).N)
		// These surfaces are explicitly unavailable with the Simple broker.
		s.request(0, "GET", prefix+"/jwks", nil, nil, 404)
		s.request(0, "GET", prefix+"/.well-known/openid-configuration", nil, nil, 404)
	}
	// The certificate endpoint reads live file contents without a restart.
	certificate(t, s.certPath, s.signer, s.caKey, s.caCert, 2)
	data, _ := s.request(0, "GET", "/api/as/certificate", nil, nil, 200)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, int64(2), cert.SerialNumber.Int64())
	// Challenge-key rotation is file/Secret based, not a Gateway rotation API.
	data, _ = s.request(0, "POST", "/api/as/challenge", map[string]any{}, nil, 200)
	oldToken := object(t, data)["extra-params"].(map[string]any)["jwt"].(string)
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	writeKey(t, s.challengePath+".new", rotated)
	require.NoError(t, os.Rename(s.challengePath+".new", s.challengePath))
	s.request(1, "POST", "/api/as/attestation", asEvidence(t, map[string]any{"challenge_token": oldToken}, "default"), nil, 401)
	data, _ = s.request(1, "POST", "/api/as/challenge", map[string]any{}, nil, 200)
	newToken := object(t, data)["extra-params"].(map[string]any)["jwt"].(string)
	verifyToken(t, newToken, &rotated.PublicKey)
	data, _ = s.request(0, "POST", "/api/as/attestation", asEvidence(t, map[string]any{"challenge_token": newToken}, "default"), nil, 200)
	verifyToken(t, string(data), &s.signer.PublicKey)
}

func (s *stack) testReferences() {
	t := s.t
	t.Log("reference registration/list refresh+append/delete and policy/RVPS cache invalidation")
	s.register(0, map[string]any{"sample.svn": "1", "persistent.value": map[string]any{"purpose": "e2e"}})
	data, _ := s.request(1, "GET", "/api/rvps/query", nil, s.adminHeaders(), 200)
	require.Contains(t, object(t, data), "persistent.value")
	runtime := map[string]any{"nonce": "e2e-cache-check"}
	s.request(0, "POST", "/api/as/attestation", asEvidence(t, runtime, "default"), nil, 200)
	s.register(1, map[string]any{"sample.svn": "2"})
	s.request(0, "POST", "/api/as/attestation", asEvidence(t, runtime, "default"), nil, 500)
	s.register(0, map[string]any{"sample.svn": "1"})
	s.request(1, "POST", "/api/as/attestation", asEvidence(t, runtime, "default"), nil, 200)
	for _, policy := range []string{allowPolicy, denyPolicy, allowPolicy} {
		s.request(1, "POST", "/api/kbs/v0/attestation-policy", map[string]any{"policy_id": "cache_policy", "policy": b64([]byte(policy))}, s.adminHeaders(), 200)
		expected := 200
		if policy == denyPolicy {
			expected = 500
		}
		s.request(0, "POST", "/api/as/attestation", asEvidence(t, runtime, "cache_policy"), nil, expected)
	}
	bundlePath := filepath.Join(s.dir, "release-manifest.json")
	for index, entry := range []struct{ digest, operation string }{{strings.Repeat("a", 64), "refresh"}, {strings.Repeat("b", 64), "add"}, {strings.Repeat("c", 64), "refresh"}} {
		writeJSON(t, bundlePath, map[string]any{"releasePayload": map[string]any{"schemaVersion": 1, "measurements": map[string]any{"cvm_container_proxy": map[string]any{"algorithm": "sha256", "value": entry.digest}}}})
		payload := map[string]any{"rv_list": []any{map[string]any{"id": "cvm_container_proxy", "version": "1.0.0", "type": "container",
			"provenance_info":   map[string]any{"type": "rv-release-manifest", "rekor_url": "https://unused.invalid", "rekor_api_version": 1},
			"provenance_source": map[string]any{"protocol": "file", "uri": bundlePath, "artifact": "bundle"}, "operation_type": entry.operation}}}
		s.request(0, "POST", "/api/rvps/set_reference_value_list", payload, s.adminHeaders(), 200)
		data, _ = s.request(1, "GET", "/api/rvps/query", nil, s.adminHeaders(), 200)
		values := object(t, data)["cvm_container_proxy"].([]any)
		require.Contains(t, values, entry.digest)
		if index == 1 {
			require.Len(t, values, 2)
		} else {
			require.Len(t, values, 1)
		}
	}
	s.request(1, "DELETE", "/api/rvps/delete/cvm_container_proxy", nil, s.adminHeaders(), 200)
	data, _ = s.request(0, "GET", "/api/rvps/query", nil, s.adminHeaders(), 200)
	require.NotContains(t, object(t, data), "cvm_container_proxy")
	s.request(0, "POST", "/api/rvps/register", "{", s.adminHeaders(), 400)
	s.request(0, "POST", "/api/rvps/set_reference_value_list", map[string]any{}, s.adminHeaders(), 400)
}

func (s *stack) testRotation(key *rsa.PrivateKey, headers map[string]string, plain, oldPublic []byte) {
	t := s.t
	t.Log("managed key reload, rewrap, rotate and other-replica cache refresh")
	data, _ := s.request(0, "POST", "/api/kbs/v0/resource/reload", nil, s.adminHeaders(), 200)
	require.GreaterOrEqual(t, object(t, data)["reloaded_keys"].(float64), float64(1))
	data, _ = s.request(0, "POST", "/api/kbs/v0/resource/rewrap", nil, s.adminHeaders(), 200)
	require.Zero(t, object(t, data)["failed"])
	data, _ = s.request(1, "POST", "/api/kbs/v0/resource/rotate", nil, s.adminHeaders(), 200)
	rotation := object(t, data)
	require.Zero(t, rotation["failed"])
	require.GreaterOrEqual(t, rotation["rewrapped"].(float64), float64(1))
	require.GreaterOrEqual(t, rotation["retired_keys"].(float64), float64(1))
	newPublic := []byte(rotation["public_key"].(string))
	require.False(t, bytes.Equal(oldPublic, newPublic), "rotation must change key generation")
	eventually(t, "rotated public key visible from replica A", func() bool {
		data, _ := s.request(0, "GET", "/api/kbs/v0/resource/pubkey", nil, s.adminHeaders(), 200)
		return bytes.Equal(data, newPublic)
	})
	s.readResource(0, resourcePath, headers, key, plain)
	second := resourcePath + "-new"
	s.request(0, "POST", second, envelope(t, newPublic, plain), s.adminHeaders(), 200)
	s.readResource(1, second, headers, key, plain)
	s.request(0, "DELETE", second, nil, s.adminHeaders(), 200)
}

func (s *stack) auditChecks(_ string) {
	t := s.t
	eventually(t, "attestation audit from real KBS and RESTful AS", func() bool {
		data, _ := s.request(1, "GET", "/api/audit/attestation?instance_id=e2e-instance&successful=true&limit=100", nil, nil, 200)
		var response struct {
			Data []struct {
				Source string `json:"source_service"`
				Body   string `json:"request_body"`
			}
			Total int
		}
		require.NoError(t, json.Unmarshal(data, &response))
		sources := map[string]bool{}
		for _, record := range response.Data {
			require.Empty(t, record.Body, "evidence must not be persisted in audit")
			sources[record.Source] = true
		}
		return sources["kbs"] && sources["attestation-service"]
	})
	eventually(t, "resource audit query filters and pagination", func() bool {
		data, _ := s.request(1, "GET", "/api/audit/resources?repository=e2e&type=secret&tag=item.v1&method=GET&successful=true&limit=1&offset=0", nil, nil, 200)
		response := object(t, data)
		return response["total"].(float64) >= 1 && len(response["data"].([]any)) == 1
	})
}

func (s *stack) testOIDC() {
	t := s.t
	t.Log("OIDC-enabled JWKS and discovery success, not only unsupported 404 coverage")
	broker := s.asConfig["attestation_token_broker"].(map[string]any)
	broker["type"] = "OIDC"
	broker["issuer_name"] = "https://e2e.invalid"
	broker["policy_dir"] = filepath.Join(s.dir, "oidc-policies")
	broker["oid_config"] = map[string]any{"issuer": "https://e2e.invalid", "jwks_uri": s.urls[0] + "/api/as/jwks", "audience": "trustee-e2e"}
	writeJSON(t, filepath.Join(s.dir, "as-config.json"), s.asConfig)
	for i := range s.rest {
		s.rest[i].stop()
		s.rest[i] = s.start(fmt.Sprintf("rest-%d", i), "restful-as", "--config-file", filepath.Join(s.dir, "as-config.json"), "--socket", s.asPorts[i])
		s.ready(s.asPorts[i])
	}
	for _, prefix := range []string{"/api/as", "/api/attestation-service"} {
		data, _ := s.request(1, "GET", prefix+"/jwks", nil, nil, 200)
		keys := object(t, data)["keys"].([]any)
		require.Len(t, keys, 1)
		require.Equal(t, b64(s.signer.N.Bytes()), keys[0].(map[string]any)["n"])
		data, _ = s.request(0, "GET", prefix+"/.well-known/openid-configuration", nil, nil, 200)
		require.Equal(t, "https://e2e.invalid", object(t, data)["issuer"])
		s.request(0, "POST", prefix+"/policy", map[string]any{"policy_id": "oidc_e2e", "policy": b64([]byte(allowPolicy))}, nil, 200)
		data, _ = s.request(1, "POST", prefix+"/attestation", asEvidence(t, map[string]any{"nonce": "oidc-e2e"}, "oidc_e2e"), nil, 200)
		claims := verifyToken(t, string(data), &s.signer.PublicKey)
		require.Equal(t, "trustee-e2e", claims["aud"])
		require.Equal(t, "https://e2e.invalid", claims["iss"])
	}
}

func (s *stack) testConcurrentWrites(upload []byte) {
	t := s.t
	t.Log("concurrent writes through independent KBS/AS/RVPS replicas retain every resource and merged reference")
	type result struct {
		status int
		err    error
		path   string
	}
	results := make(chan result, 8)
	for i := 0; i < 8; i++ {
		message := map[string]any{"version": "0.1.0", "type": "sample", "payload": base64.StdEncoding.EncodeToString(jsonBytes(t, map[string]any{"concurrent.merge": []string{fmt.Sprint(i)}}))}
		registration := jsonBytes(t, map[string]any{"message": string(jsonBytes(t, message))})
		go func(index int, registration []byte) {
			for _, operation := range []struct {
				path string
				body []byte
			}{{fmt.Sprintf("/api/kbs/v0/resource/e2e/concurrent/item-%d", index), upload}, {"/api/rvps/register", registration}} {
				req, err := http.NewRequest("POST", s.urls[index%2]+operation.path, bytes.NewReader(operation.body))
				if err != nil {
					results <- result{err: err}
					return
				}
				req.Header.Set("Authorization", "Bearer "+s.admin)
				req.Header.Set("Content-Type", "application/json")
				resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
				if err != nil {
					results <- result{err: err}
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != 200 {
					results <- result{status: resp.StatusCode, path: operation.path}
					return
				}
			}
			results <- result{status: 200}
		}(i, registration)
	}
	completed := make([]result, 0, 8)
	for i := 0; i < 8; i++ {
		completed = append(completed, <-results)
	}
	for _, got := range completed {
		require.NoError(t, got.err)
		require.Equal(t, 200, got.status, "concurrent POST %s", got.path)
	}
	data, _ := s.request(1, "GET", "/api/kbs/v0/resources", nil, s.adminHeaders(), 200)
	for i := 0; i < 8; i++ {
		require.Contains(t, string(data), fmt.Sprintf("item-%d", i))
		s.request(i%2, "DELETE", fmt.Sprintf("/api/kbs/v0/resource/e2e/concurrent/item-%d", i), nil, s.adminHeaders(), 200)
	}
	data, _ = s.request(0, "GET", "/api/rvps/query", nil, s.adminHeaders(), 200)
	values := object(t, data)["concurrent.merge"].([]any)
	require.Len(t, values, 8)
	for i := 0; i < 8; i++ {
		require.Contains(t, values, fmt.Sprint(i))
	}
	s.request(1, "DELETE", "/api/rvps/delete/concurrent.merge", nil, s.adminHeaders(), 200)
}
