# NVIDIA GPU verification for TDX evidence

The embedded TDX GPU evidence path supports Hopper and Blackwell. Verification
defaults to **local RIM mode**. NRAS is a separate, explicitly selected mode.
There is no automatic fallback between modes and no successful bypass mode.

## Configuration

AS configuration is optional. Without NVIDIA settings, local RIM mode uses the
official NVIDIA RIM and OCSP services and `/usr/bin/nvattest`.
Install NVIDIA **NVAT 2.0.0 or later** (`nvattest` and `libnvat`) on the verifier
host or inside its container. CPU-only attestation does not invoke NVAT.
See [NVIDIA downloads](https://developer.nvidia.com/nvat-downloads) and the
[official CLI reference](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/2.0.0/sdk-cli/command-reference.html).

Standalone AS JSON configuration:

```json
{
  "nvidia_verifier": {
    "mode": "rim",
    "local_verifier_path": "/usr/bin/nvattest",
    "rim_url": "https://rim.attestation.nvidia.com",
    "ocsp_url": "https://ocsp.ndis.nvidia.com"
  }
}
```

For KBS with built-in AS, the same settings appear in KBS TOML:

```toml
[attestation_service.nvidia_verifier]
mode = "rim"
local_verifier_path = "/usr/bin/nvattest"
```

To select NRAS instead, set `mode = "nras"`. NRAS mode does not require NVAT.
Wasm supports NRAS; local RIM mode requires a native verifier process.
An AS library instance can use `AttestationService::with_nvidia_config`.

Each environment variable overrides its corresponding file setting:

| Environment | File field | Default |
| --- | --- | --- |
| `TRUSTEE_NVIDIA_VERIFIER_MODE` | `mode` | `rim` (`local` alias); `nras` (`remote` alias) |
| `TRUSTEE_NVIDIA_LOCAL_VERIFIER_PATH` | `local_verifier_path` | `/usr/bin/nvattest` |
| `TRUSTEE_NVIDIA_RIM_URL` | `rim_url` | `https://rim.attestation.nvidia.com` |
| `TRUSTEE_NVIDIA_OCSP_URL` | `ocsp_url` | `https://ocsp.ndis.nvidia.com` |
| `TRUSTEE_NVIDIA_NRAS_URL` | `nras_url` | `https://nras.attestation.nvidia.com/v4/attest/gpu` |
| `TRUSTEE_NVIDIA_NRAS_JWKS_URL` | `nras_jwks_url` | `https://nras.attestation.nvidia.com/.well-known/jwks.json` |
| `TRUSTEE_NVIDIA_TLS_CA_CERT` | `tls_ca_cert` | NVAT's system default CA bundle |

`tls_ca_cert` configures the local NVAT client's TLS trust. On RPM-based systems
whose CA bundle is not `/etc/ssl/certs/ca-certificates.crt`, use
`/etc/pki/tls/certs/ca-bundle.crt`. Paths must be absolute and service URLs HTTPS.
Invalid overrides reject verification. The legacy `NV_RIM_URL` and
`set_rim_service_url` affect local RIM selection; the new environment setting
takes priority. Legacy `/v1/rim` URL suffixes are normalized to SDK base URLs.
The executable path is operator-controlled and must identify the trusted NVAT
binary, never a guest-supplied executable.

```sh
export TRUSTEE_NVIDIA_VERIFIER_MODE=nras
# To override a file configured for NRAS:
export TRUSTEE_NVIDIA_VERIFIER_MODE=rim
```

## Verification and policy boundary

Local mode invokes `nvattest attest --verifier local` on the exact supplied
report and certificate using a private temporary file, a 120-second deadline,
and bounded output. NVAT verifies device report signatures and NVIDIA chains,
FWID and nonce binding, certificate expiration and OCSP, authenticated RIMs,
and driver/VBIOS measurements. No evidence is submitted to NRAS in this mode.
The SDK process isolates its global OpenSSL/XML initialization from Trustee.

NRAS mode posts the same evidence with claims version 4.0, authenticates both
ES384 JWTs using trusted NRAS JWKS, checks issuer/expiry/not-before, compares
both EAT nonces, and verifies the overall JWT's digest of the detached JWT.
Both modes require successful signature/RIM/OCSP results, secure boot,
disabled debugging and a verified device identity. Unknown, missing, revoked,
expired or negative results reject the entire attestation before policy.
Neither path reads or transmits cloud service keys.

Only authenticated vendor claims appear as `tdx["nvidia_gpu.0"]`, etc.;
`tdx.nvidia_gpu_count` is the number of distinct verified `ueid` identities.
The `verifier` field is `rim` or `nras`. Guest UUID/name/CC-state/version labels
are not promoted into authenticated claims. Existing GPU policies using the
old guest `cc_enabled` or unsigned `measurement` field must be updated.

A deployment requiring GPUs must additionally require the expected count and
approved identities in its attestation or resource policy. For example, a
Rego condition for two specified devices is:

```rego
input.tdx.nvidia_gpu_count == 2
input.tdx["nvidia_gpu.0"].ueid in query_reference_value("allowed_gpu_identities")
input.tdx["nvidia_gpu.1"].ueid in query_reference_value("allowed_gpu_identities")
```

Combine this with the deployment's existing CPU measurements and trust-vector
requirements. A valid CPU-only quote is not evidence that the platform has the
required GPUs. Guest enumeration and its CC-state label do not independently
prove physical topology, device completeness or CC mode.

## CPU/GPU binding and upgrade

Upgrade guest-components and Trustee together for GPU workloads. CPU-only
evidence retains its existing report-data format. Old GPU evidence lacking
`binding_version = 1` is rejected because it does not bind the device set.
`TRUSTEE_SKIP_NVGPU_VERIFY=true` and `set_skip_gpu_verify(Some(true))` now reject
GPU-bearing evidence rather than producing unverified claims.

Guest Rust and Go collectors must obtain a report and chain for every
discovered GPU. They generate the primary TDX quote **after** collection, using:

```text
R = original report_data, right-padded to 64 bytes
GPU requester nonce = SHA256("tdx-nvidia-nonce-v1\0" || R)
TDX REPORT_DATA = SHA512("tdx-nvidia-evidence-v1\0" || R || LE32(count) || devices)
device = LE32(index) || field(architecture) || field(report) || field(certificate)
field(bytes) = LE32(byte_length) || bytes
```

Architecture is uppercase ASCII, and report/certificate are decoded bytes.
Device order is preserved. Collection timestamp and guest metadata are not
security inputs. A GPU deletion, reordering or substitution changes the CPU
commitment. Trustee also rejects repeated authenticated device identities.
The same independent Python-generated vector is tested by both Rust crates and
the Go collector.

## Reproduce real-evidence tests

Fixtures are public hardware reports and certificates from CoCo; see
[fixture provenance](../../test_data/nvidia/README.md). They contain a fixed
challenge and cannot answer a fresh request.

```sh
cargo +1.88.0 test -p verifier --no-default-features --features tdx-dcap-rust --lib

# Requires NVAT 2.x, RIM/OCSP and NRAS connectivity. No GPU is required to replay
# these real reports. Optionally set the executable and CA paths above.
cargo +1.88.0 test -p verifier --no-default-features --features tdx-dcap-rust \
  nvidia::tests::live_real --lib -- --ignored --test-threads=1
```

On 2026-11-17, Blackwell report verification passed in both modes; wrong nonce,
changed signature and a substituted certificate were rejected. The old Hopper
report was rejected because its Driver RIM signing certificate expired on
2026-06-01. These fixed-challenge tests validate hardware-report replay and
live verifier services; fresh collection is covered separately below.

For a fresh hardware run, build the paired guest-components `evidence_getter`
with `tdx-attester,bin` (Rust) or `-tags gpu` (Go). On the TDX/GPU guest,
generate a random 64-byte challenge and collect evidence:

```sh
head -c 64 /dev/urandom > report-data.bin
./evidence_getter file report-data.bin > evidence.json
```

Transfer these two files to the verifier over an authenticated channel; keep
device-specific evidence outside the source tree. Then run each mode explicitly:

```sh
export TRUSTEE_NVIDIA_HARDWARE_EVIDENCE=/absolute/path/evidence.json
export TRUSTEE_NVIDIA_HARDWARE_REPORT_DATA=/absolute/path/report-data.bin
for mode in rim nras; do
  TRUSTEE_NVIDIA_VERIFIER_MODE=$mode cargo +1.88.0 test -p verifier \
    --no-default-features --features tdx-dcap-rust --lib \
    nvidia::tests::live_hardware -- --ignored --nocapture --test-threads=1
done
```

The GPU test verifies the supplied report and rejects a wrong nonce, changed
signature and substituted certificate. RIM mode uses unreachable NRAS URLs.
The combined test additionally checks the TDX signature, event log, CPU/GPU
binding, and rejection of a changed challenge or removed GPU evidence. It
requires a working quote-generation service and PCCS connectivity.

## H20 hardware validation (2026-11-17)

Fresh evidence was collected on an Alibaba Cloud `ecs.gn8v-tee.4xlarge` in
`cn-beijing-l`: one NVIDIA H20, GPU CC ON, driver `595.71.05`, VBIOS
`96.00.CF.00.05`, and ALinux kernel `5.10.134-19.8.al8.x86_64`. The guest used
an 8 GiB SWIOTLB and NVIDIA persistence daemon as described in the
[provider instructions](https://help.aliyun.com/en/ecs/user-guide/build-a-heterogeneous-confidential-computing-environment).

| Collector | Local RIM/OCSP | NRAS | Full TDX/GPU binding |
| --- | --- | --- | --- |
| Rust, paired guest-components PR | Passed | Passed | Passed in both modes |
| Go, built with `-tags gpu` | Passed | Passed | Passed in both modes |

Each collector returned a 5006-byte TDX quote, a 4129-byte GPU report and a
4826-byte attestation certificate chain for a random 64-byte challenge. The
GPU tests rejected a wrong nonce, modified signature and substituted chain.
The combined verifier rejected a changed challenge, removed GPU evidence and
modified GPU report. Local tests used unreachable NRAS URLs.

Hardware testing also reproduced NVML returning zero devices after GPU
initialization failed. The paired collectors now reject this PCI/NVML
inventory mismatch. Rust additionally selects the GPU attestation chain
instead of the empty CEC chain and slices both NVML buffers by their reported
lengths. Both fixes were validated on the same H20 before releasing the
temporary instance. This run covers fresh collection and combined evidence
verification; it does not exercise KBS secret delivery.
