//go:build e2e

// Copyright (c) 2026 Alibaba. SPDX-License-Identifier: Apache-2.0
package e2e

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func jsonBytes(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return data
}
func object(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var value map[string]any
	require.NoError(t, json.Unmarshal(data, &value))
	return value
}
func b64(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
func unb64(t *testing.T, value string) []byte {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(value)
	require.NoError(t, err)
	return data
}

func adminToken(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	unsigned := b64([]byte(`{"alg":"EdDSA","typ":"JWT"}`)) + "." + b64(jsonBytes(t, map[string]any{"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}))
	return unsigned + "." + b64(ed25519.Sign(key, []byte(unsigned)))
}

func expiredChallenge(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	unsigned := b64([]byte(`{"alg":"RS384","typ":"JWT"}`)) + "." + b64(jsonBytes(t, map[string]any{"nonce": "expired-e2e-challenge", "iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix()}))
	hash := sha512.Sum384([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA384, hash[:])
	require.NoError(t, err)
	return unsigned + "." + b64(signature)
}

// Verify the issuer signature with the fixture's independently held public key,
// not just with an untrusted key copied out of the token being tested.
func verifyToken(t *testing.T, token string, key *rsa.PublicKey) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Equal(t, 3, len(parts), "invalid JWT shape")
	header := object(t, unb64(t, parts[0]))
	var alg crypto.Hash
	var digest []byte
	switch header["alg"] {
	case "RS384":
		alg = crypto.SHA384
		sum := sha512.Sum384([]byte(parts[0] + "." + parts[1]))
		digest = sum[:]
	case "RS256":
		alg = crypto.SHA256
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		digest = sum[:]
	default:
		t.Fatal("unexpected JWT algorithm")
	}
	require.NoError(t, rsa.VerifyPKCS1v15(key, alg, digest, unb64(t, parts[2])))
	claims := object(t, unb64(t, parts[1]))
	require.Greater(t, claims["exp"].(float64), float64(time.Now().Unix()))
	return claims
}

func teeKey(t *testing.T, key *rsa.PrivateKey) map[string]any {
	t.Helper()
	return map[string]any{"kty": "RSA", "alg": "RSA-OAEP-256", "n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}
}

func sampleEvidence(t *testing.T, runtime map[string]any) map[string]any {
	t.Helper()
	hash := sha512.Sum384(jsonBytes(t, runtime))
	return map[string]any{"svn": "1", "report_data": base64.StdEncoding.EncodeToString(hash[:]), "measure_register": strings.Repeat("0", 64)}
}

func asEvidence(t *testing.T, runtime map[string]any, policies ...string) map[string]any {
	t.Helper()
	return map[string]any{"verification_requests": []any{map[string]any{"tee": "sample",
		"evidence": b64(jsonBytes(t, sampleEvidence(t, runtime))), "runtime_data": map[string]any{"structured": runtime}, "runtime_data_hash_algorithm": "sha384"}}, "policy_ids": policies}
}

// The storage envelope uses STANDARD base64 and no AAD. The outer KBS JWE
// uses URL_SAFE_NO_PAD and authenticates the encoded protected header.
func envelope(t *testing.T, publicPEM, plain []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(publicPEM)
	require.NotNil(t, block)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	key, ok := parsed.(*rsa.PublicKey)
	require.True(t, ok)
	cek, iv := make([]byte, 32), make([]byte, 12)
	_, err = rand.Read(cek)
	require.NoError(t, err)
	_, err = rand.Read(iv)
	require.NoError(t, err)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, cek, nil)
	require.NoError(t, err)
	blockCipher, err := aes.NewCipher(cek)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(blockCipher)
	require.NoError(t, err)
	ciphertext := aead.Seal(nil, iv, plain, nil)
	return jsonBytes(t, map[string]any{"alg": "RSA-OAEP-256", "enc_key": base64.StdEncoding.EncodeToString(wrapped),
		"iv": base64.StdEncoding.EncodeToString(iv), "ciphertext": base64.StdEncoding.EncodeToString(ciphertext[:len(ciphertext)-16]), "tag": base64.StdEncoding.EncodeToString(ciphertext[len(ciphertext)-16:])})
}

func decryptResource(t *testing.T, key *rsa.PrivateKey, data []byte) []byte {
	t.Helper()
	jwe := object(t, data)
	header := object(t, unb64(t, jwe["protected"].(string)))
	require.Equal(t, "RSA-OAEP-256", header["alg"])
	require.Equal(t, "A256GCM", header["enc"])
	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, unb64(t, jwe["encrypted_key"].(string)), nil)
	require.NoError(t, err)
	block, err := aes.NewCipher(cek)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	ciphertext := append(unb64(t, jwe["ciphertext"].(string)), unb64(t, jwe["tag"].(string))...)
	plain, err := aead.Open(nil, unb64(t, jwe["iv"].(string)), ciphertext, []byte(jwe["protected"].(string)))
	require.NoError(t, err)
	return plain
}
