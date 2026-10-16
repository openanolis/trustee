#!/usr/bin/env bash
set -euo pipefail

trustee_repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$trustee_repo"
# Keep pure-Rust RSA key generation and Argon2 realistic without a full release
# build. These settings apply only to this test invocation, not production.
export CARGO_PROFILE_DEV_OPT_LEVEL="${CARGO_PROFILE_DEV_OPT_LEVEL:-1}"
export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"
trustee_features='kbs/coco-as-grpc,kbs/encrypted-db,kbs/encrypted-local-fs,attestation-service/restful-bin,attestation-service/grpc-bin,attestation-service/rvps-grpc,attestation-service/shared-storage-mysql,reference-value-provider-service/bin'
if [[ "${TRUSTEE_E2E_REGOVM:-0}" == 1 ]]; then
  trustee_features+=',attestation-service/regorus-regovm'
fi
if [[ "${TRUSTEE_E2E_SKIP_BUILD:-0}" != 1 ]]; then
  cargo build --locked --no-default-features -p kbs -p attestation-service \
    -p reference-value-provider-service --bins --features "$trustee_features"
fi
export TRUSTEE_E2E_BIN_DIR="${TRUSTEE_E2E_BIN_DIR:-${CARGO_TARGET_DIR:-$trustee_repo/target}/debug}"
if [[ "$TRUSTEE_E2E_BIN_DIR" != /* ]]; then
  export TRUSTEE_E2E_BIN_DIR="$trustee_repo/$TRUSTEE_E2E_BIN_DIR"
fi
cd trustee-gateway
if [[ "${TRUSTEE_E2E_SKIP_BUILD:-0}" != 1 ]]; then
  go build -buildvcs=false -o "$TRUSTEE_E2E_BIN_DIR/trustee-gateway" ./cmd/server
fi
go test -tags=e2e -count=1 -timeout=20m -v ./test/e2e
