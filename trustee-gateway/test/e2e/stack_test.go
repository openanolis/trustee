//go:build e2e

// Copyright (c) 2026 Alibaba. SPDX-License-Identifier: Apache-2.0
package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

type apiRoute struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type service struct {
	cmd  *exec.Cmd
	done chan error
	name string
}

func (p *service) stop() {
	if p == nil || p.cmd == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
	p.cmd = nil
}

type stack struct {
	t                               *testing.T
	dir, bin, mode, backend         string
	shared                          bool
	admin                           string
	signer                          *rsa.PrivateKey
	caKey                           *rsa.PrivateKey
	caCert                          *x509.Certificate
	challengePath, certPath         string
	asConfig                        map[string]any
	urls                            []string
	kbsPorts, asPorts, gatewayPorts []string
	rvpsPorts, grpcPorts            []string
	processes                       []*service
	kbs, rest, gateway, rvps, grpc  []*service
	coverage                        map[apiRoute]int
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
}

func port(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func eventually(t *testing.T, description string, f func() bool) {
	t.Helper()
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if f() {
			return
		}
		select {
		case <-timer.C:
			t.Fatalf("timed out: %s", description)
		case <-ticker.C:
		}
	}
}

func (s *stack) start(name, binary string, args ...string) *service {
	s.t.Helper()
	log, err := os.OpenFile(filepath.Join(s.dir, name+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(s.t, err)
	cmd := exec.Command(filepath.Join(s.bin, binary), args...)
	// An operator's environment must never redirect this isolated stack to a
	// real resource backend or production Gateway database.
	for _, variable := range os.Environ() {
		if strings.HasPrefix(variable, "KBS_RESOURCE_") || strings.HasPrefix(variable, "TRUSTEE_STORAGE_") || strings.HasPrefix(variable, "TRUSTEE_GATEWAY_DATABASE_DSN=") || strings.HasPrefix(variable, "KBS_CONFIG_FILE=") {
			continue
		}
		cmd.Env = append(cmd.Env, variable)
	}
	cmd.Env = append(cmd.Env, "RUST_LOG=error", "GIN_MODE=release", "TOKIO_WORKER_THREADS=2")
	cmd.Stdout, cmd.Stderr = log, log
	require.NoError(s.t, cmd.Start(), "start %s", name)
	p := &service{cmd: cmd, done: make(chan error, 1), name: name}
	go func() { p.done <- cmd.Wait(); _ = log.Close(); close(p.done) }()
	s.processes = append(s.processes, p)
	return p
}

func (s *stack) ready(addr string) {
	s.t.Helper()
	process := s.processes[len(s.processes)-1]
	defer func() {
		if s.t.Failed() {
			s.logFailure(process.name)
		}
	}()
	eventually(s.t, "service listening on "+addr, func() bool {
		select {
		case <-process.done:
			s.t.Fatalf("service %s exited before readiness", process.name)
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
}

func (s *stack) logFailure(name string) {
	data, err := os.ReadFile(filepath.Join(s.dir, name+".log"))
	if err != nil {
		return
	}
	// Diagnostics never print authentication material, evidence or DSNs.
	private := regexp.MustCompile(`(?i)token|cookie|nonce|runtime|evidence|secret|password|passphrase|credential|bearer|private|mysql://|[a-z0-9_-]{20,}\.[a-z0-9_-]{20,}\.`)
	lines := strings.Split(string(data), "\n")
	start := len(lines) - 12
	if start < 0 {
		start = 0
	}
	for _, line := range lines[start:] {
		if line != "" && !private.MatchString(line) {
			if len(line) > 500 {
				line = line[:500]
			}
			s.t.Logf("%s: %s", name, line)
		}
	}
}

// Create and later drop only a fresh database owned by this test. Never reset
// tables in a caller-provided database or accept a non-loopback database host.
func testDatabase(t *testing.T) (string, string) {
	t.Helper()
	raw := os.Getenv("MYSQL_TEST_URL")
	require.NotEmpty(t, raw, "MYSQL_TEST_URL is required; MySQL E2E must not silently skip")
	u, err := url.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, "mysql", u.Scheme)
	require.NotNil(t, u.User, "MYSQL_TEST_URL must specify a test database user")
	require.Contains(t, []string{"127.0.0.1", "localhost", "::1"}, u.Hostname(), "E2E only accepts loopback MySQL")
	password, _ := u.User.Password()
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr = u.User.Username(), password, "tcp", u.Host
	cfg.ParseTime = true
	cfg.Timeout = 5 * time.Second
	db, err := sql.Open("mysql", cfg.FormatDSN())
	require.NoError(t, err)
	random := make([]byte, 8)
	_, err = rand.Read(random)
	require.NoError(t, err)
	name := fmt.Sprintf("trustee_e2e_%x", random)
	eventually(t, "isolated MySQL availability", func() bool { return db.Ping() == nil })
	_, err = db.Exec("CREATE DATABASE `" + name + "`")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec("DROP DATABASE `" + name + "`")
		if err != nil {
			t.Error("could not remove isolated E2E database")
		}
		_ = db.Close()
	})
	cfg.DBName = name
	u.Path = "/" + name
	return u.String(), cfg.FormatDSN()
}

func writeKey(t *testing.T, path string, key any) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600))
}

func certificate(t *testing.T, path string, key, caKey *rsa.PrivateKey, caCert *x509.Certificate, serial int64) {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Trustee E2E only"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	require.NoError(t, os.WriteFile(path, chain, 0600))
}

func newStack(t *testing.T, mode, backend string, shared bool) *stack {
	t.Helper()
	s := &stack{t: t, dir: t.TempDir(), bin: os.Getenv("TRUSTEE_E2E_BIN_DIR"), mode: mode, backend: backend, shared: shared, coverage: map[apiRoute]int{}}
	require.NotEmpty(t, s.bin, "run test/e2e/run.sh to build the real service binaries")
	for _, binary := range []string{"kbs", "grpc-as", "restful-as", "rvps", "trustee-gateway"} {
		_, err := os.Stat(filepath.Join(s.bin, binary))
		require.NoError(t, err, "missing real binary %s", binary)
	}
	var storage any
	var rustDSN, goDSN string
	if shared {
		rustDSN, goDSN = testDatabase(t)
		storage = map[string]any{"storage_type": "mysql", "require_shared": true,
			"backends": map[string]any{"mysql": map[string]any{"url": rustDSN, "url_env": nil, "max_connections": 5}}}
	}
	// Registered last, this cleanup stops all processes before dropping MySQL.
	t.Cleanup(func() {
		for i := len(s.processes) - 1; i >= 0; i-- {
			s.processes[i].stop()
		}
		if t.Failed() {
			names := map[string]bool{}
			for _, process := range s.processes {
				if !names[process.name] {
					s.logFailure(process.name)
					names[process.name] = true
				}
			}
		}
	})
	_, adminKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	adminDER, err := x509.MarshalPKIXPublicKey(adminKey.Public())
	require.NoError(t, err)
	adminPath := filepath.Join(s.dir, "admin.pub")
	require.NoError(t, os.WriteFile(adminPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: adminDER}), 0600))
	s.admin = adminToken(t, adminKey)
	s.signer, err = rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	s.caKey, err = rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Trustee E2E CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &s.caKey.PublicKey, s.caKey)
	require.NoError(t, err)
	s.caCert, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPath := filepath.Join(s.dir, "ca.crt")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600))
	signerPath := filepath.Join(s.dir, "signer.pem")
	writeKey(t, signerPath, s.signer)
	s.certPath = filepath.Join(s.dir, "signer.crt")
	certificate(t, s.certPath, s.signer, s.caKey, s.caCert, 1)
	s.challengePath = filepath.Join(s.dir, "challenge.pem")
	writeKey(t, s.challengePath, s.signer)
	masterPath := filepath.Join(s.dir, "master.passphrase")
	master := make([]byte, 32)
	_, err = rand.Read(master)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(masterPath, master, 0600))
	credentialPath := filepath.Join(s.dir, "credential")
	require.NoError(t, os.WriteFile(credentialPath, []byte("synthetic-e2e-credential"), 0600))
	rvpsConfig := map[string]any{"storage": map[string]any{"type": "LocalJson", "file_path": filepath.Join(s.dir, "rvps.json")}}
	if shared {
		rvpsConfig["storage_backend"] = storage
		rvpsConfig["storage"] = map[string]any{"type": "SharedStore"}
	}
	s.asConfig = map[string]any{"work_dir": filepath.Join(s.dir, "as"), "challenge_key_path": s.challengePath,
		"attestation_token_broker": map[string]any{"type": "Simple", "issuer_name": "trustee-e2e", "duration_min": 5,
			"policy_dir": filepath.Join(s.dir, "simple-policies"), "signer": map[string]any{"key_path": signerPath, "cert_path": s.certPath}}}
	if shared {
		s.asConfig["storage_backend"] = storage
	}
	replicas := 1
	if shared {
		replicas = 2
	}
	for i := 0; i < replicas; i++ {
		rvpsAddr, grpcAddr := port(t), port(t)
		s.rvpsPorts = append(s.rvpsPorts, rvpsAddr)
		s.grpcPorts = append(s.grpcPorts, grpcAddr)
		rvpsPath := filepath.Join(s.dir, fmt.Sprintf("rvps-%d.json", i))
		writeJSON(t, rvpsPath, rvpsConfig)
		s.rvps = append(s.rvps, s.start(fmt.Sprintf("rvps-%d", i), "rvps", "--config", rvpsPath, "--address", rvpsAddr))
		s.ready(rvpsAddr)
		asConfig := object(t, jsonBytes(t, s.asConfig))
		asConfig["rvps_config"] = map[string]any{"type": "GrpcRemote", "address": "http://" + rvpsAddr}
		asPath := filepath.Join(s.dir, fmt.Sprintf("as-%d.json", i))
		writeJSON(t, asPath, asConfig)
		s.grpc = append(s.grpc, s.start(fmt.Sprintf("grpc-as-%d", i), "grpc-as", "--config-file", asPath, "--socket", grpcAddr))
		s.ready(grpcAddr)
		asAddr, kbsAddr, gatewayAddr := port(t), port(t), port(t)
		s.asPorts = append(s.asPorts, asAddr)
		s.kbsPorts = append(s.kbsPorts, kbsAddr)
		s.gatewayPorts = append(s.gatewayPorts, gatewayAddr)
		s.rest = append(s.rest, s.start(fmt.Sprintf("rest-%d", i), "restful-as", "--config-file", asPath, "--socket", asAddr))
		s.ready(asAddr)
		resource := map[string]any{"name": "resource", "type": backend, "dir_path": filepath.Join(s.dir, "resources")}
		switch backend {
		case "EncryptedLocalFs":
			resource["key_dir"] = filepath.Join(s.dir, "resource-keys")
		case "EncryptedDb":
			resource["master_secret_path"] = masterPath
			resource["bump_poll_interval_ms"] = 50
			if shared {
				resource["database"] = map[string]any{"type": "mysql", "dsn": rustDSN}
			} else {
				resource["database"] = map[string]any{"type": "sqlite", "path": filepath.Join(s.dir, "resources.db")}
			}
		}
		kbsConfig := map[string]any{"http_server": map[string]any{"insecure_http": true, "sockets": []string{kbsAddr}},
			"admin":               map[string]any{"insecure_api": false, "auth_public_key": adminPath},
			"attestation_token":   map[string]any{"insecure_key": false, "trusted_certs_paths": []string{caPath}},
			"attestation_service": map[string]any{"type": "coco_as_grpc", "as_addr": "http://" + grpcAddr, "timeout": 120},
			"policy_engine":       map[string]any{"policy_path": filepath.Join(s.dir, "resource-policy.rego")}, "plugins": []any{resource}}
		if shared {
			kbsConfig["storage_backend"] = storage
		}
		kbsPath := filepath.Join(s.dir, fmt.Sprintf("kbs-%d.json", i))
		writeJSON(t, kbsPath, kbsConfig)
		s.kbs = append(s.kbs, s.start(fmt.Sprintf("kbs-%d", i), "kbs", "--config-file", kbsPath))
		s.ready(kbsAddr)
		dbConfig := map[string]any{"type": "sqlite", "path": filepath.Join(s.dir, "gateway.db"), "use_memory": true, "backup_interval": "1h", "enable_backup_on_shutdown": true}
		if shared {
			dbConfig = map[string]any{"type": "mysql", "require_shared": true, "dsn": goDSN, "max_open_conns": 5, "max_idle_conns": 2}
		}
		_, portString, _ := net.SplitHostPort(gatewayAddr)
		gatewayConfig := map[string]any{"server": map[string]any{"host": "127.0.0.1", "port": json.Number(portString), "insecure_http": true},
			"kbs": map[string]any{"url": "http://" + kbsAddr}, "attestation_service": map[string]any{"url": "http://" + asAddr},
			"rvps": map[string]any{"grpc_addr": rvpsAddr}, "database": dbConfig, "logging": map[string]any{"level": "error"},
			"credential": map[string]any{"path": credentialPath}}
		gatewayPath := filepath.Join(s.dir, fmt.Sprintf("gateway-%d.json", i))
		writeJSON(t, gatewayPath, gatewayConfig)
		s.gateway = append(s.gateway, s.start(fmt.Sprintf("gateway-%d", i), "trustee-gateway", "--config", gatewayPath))
		s.ready(gatewayAddr)
		if shared && i == 0 {
			db, err := sql.Open("mysql", goDSN)
			require.NoError(t, err)
			for _, table := range []string{"attestation_records", "resource_requests", "aa_instance_heartbeats"} {
				var format string
				err = db.QueryRow("SELECT ROW_FORMAT FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&format)
				require.NoError(t, err)
				require.Equal(t, "dynamic", strings.ToLower(format), "wide Gateway table %s must not inherit COMPACT", table)
			}
			require.NoError(t, db.Close())
		}
		s.urls = append(s.urls, "http://"+gatewayAddr)
	}
	if !shared {
		s.urls = append(s.urls, s.urls[0])
	}
	s.asConfig["rvps_config"] = map[string]any{"type": "GrpcRemote", "address": "http://" + s.rvpsPorts[0]}
	return s
}

func (s *stack) restartReplica(i int) {
	s.t.Helper()
	if !s.shared {
		i = 0
	}
	s.gateway[i].stop()
	s.kbs[i].stop()
	s.rest[i].stop()
	s.grpc[i].stop()
	s.rvps[i].stop()
	s.rvps[i] = s.start(fmt.Sprintf("rvps-%d", i), "rvps", "--config", filepath.Join(s.dir, fmt.Sprintf("rvps-%d.json", i)), "--address", s.rvpsPorts[i])
	s.ready(s.rvpsPorts[i])
	asPath := filepath.Join(s.dir, fmt.Sprintf("as-%d.json", i))
	s.grpc[i] = s.start(fmt.Sprintf("grpc-as-%d", i), "grpc-as", "--config-file", asPath, "--socket", s.grpcPorts[i])
	s.ready(s.grpcPorts[i])
	s.rest[i] = s.start(fmt.Sprintf("rest-%d", i), "restful-as", "--config-file", asPath, "--socket", s.asPorts[i])
	s.ready(s.asPorts[i])
	s.kbs[i] = s.start(fmt.Sprintf("kbs-%d", i), "kbs", "--config-file", filepath.Join(s.dir, fmt.Sprintf("kbs-%d.json", i)))
	s.ready(s.kbsPorts[i])
	s.gateway[i] = s.start(fmt.Sprintf("gateway-%d", i), "trustee-gateway", "--config", filepath.Join(s.dir, fmt.Sprintf("gateway-%d.json", i)))
	s.ready(s.gatewayPorts[i])
}

func (s *stack) request(replica int, method, path string, body any, headers map[string]string, expected int) ([]byte, http.Header) {
	s.t.Helper()
	var payload []byte
	switch b := body.(type) {
	case nil:
	case []byte:
		payload = b
	case string:
		payload = []byte(b)
	default:
		var err error
		payload, err = json.Marshal(b)
		require.NoError(s.t, err)
	}
	req, err := http.NewRequest(method, s.urls[replica]+path, bytes.NewReader(payload))
	require.NoError(s.t, err)
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	require.NoError(s.t, err, "%s %s", method, path)
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	require.NoError(s.t, err)
	// Never include response bodies, bearer tokens, cookies or evidence in logs.
	require.Equal(s.t, expected, resp.StatusCode, "%s %s (response bytes: %d)", method, path, len(data))
	u, err := url.Parse(path)
	require.NoError(s.t, err)
	for _, route := range contract(s.t) {
		if route.Method == method && matches(route.Path, u.Path) && expected >= 200 && expected < 300 {
			s.coverage[route]++
		}
	}
	return data, resp.Header
}

func (s *stack) adminHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer " + s.admin}
}

func contract(t *testing.T) []apiRoute {
	t.Helper()
	data, err := os.ReadFile("api-contract.json")
	require.NoError(t, err)
	var routes []apiRoute
	require.NoError(t, json.Unmarshal(data, &routes))
	return routes
}

func matches(pattern, path string) bool {
	left, right := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if !strings.HasPrefix(left[i], ":") && left[i] != right[i] {
			return false
		}
	}
	return true
}
