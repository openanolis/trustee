#!/usr/bin/env bash
# Runs inside a TDX guest. Only the digest of the random test resource leaves stdout.
set -euo pipefail
[[ $# == 1 && $1 =~ ^shelter-e2e/secret/e2e[0-9a-f]{24}$ ]] || {
    echo "expected a Shelter E2E resource path" >&2
    exit 2
}
grep -qw tdx_guest /proc/cpuinfo || [[ -c /dev/tdx_guest || -c /dev/tdx-guest ]] || {
    echo "TDX guest interface not found" >&2
    exit 1
}
: "${TRUSTEE_URL:=https://127.0.0.1:8082}"
: "${TRUSTEE_CA_FILE:=/var/lib/trustee-shelter/identity/ca.crt}"
[[ $TRUSTEE_URL == https://* && -s $TRUSTEE_CA_FILE ]] || {
    echo "expected HTTPS and a readable Trustee CA certificate" >&2
    exit 1
}
args=(--url "$TRUSTEE_URL" --cert-file "$TRUSTEE_CA_FILE")
# The native TDX build of trustee-attester creates a fresh RCAR session, validates
# the JWE and returns the decrypted bytes as base64. No administrator token is used.
unset TRUSTEE_API_KEY
RUST_LOG=off trustee-attester "${args[@]}" get-resource --path "$1" 2>/dev/null |
    base64 --decode |
    sha256sum |
    cut -d' ' -f1
