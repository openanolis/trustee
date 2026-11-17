# Public NVIDIA hardware evidence fixtures

Copied unchanged from Confidential Containers Trustee, commit
`564a3ba51eaedd4734e88e1883a905dd780ee45b`, under Apache-2.0:

- [Blackwell report and certificate chain](https://github.com/confidential-containers/trustee/tree/564a3ba51eaedd4734e88e1883a905dd780ee45b/deps/verifier/test_data/nvidia):
  `blackwell_coco_report.txt` and `blackwell_coco_certs.txt`.
  The public report identifies driver `595.58.03`, VBIOS `98.02.74.00.01`, and
  hardware model `GB20X A01 GSP BROM` after successful vendor verification.
- `hopperAttestationReport.txt` and `hopper_cert_chain_case1.txt` are the CoCo
  Hopper fixture, with driver `550.90.07` and VBIOS `96.00.9F.00.01`.
  Its Driver RIM certificate expired on 2026-06-01; full verification must fail.

These files contain public certificate chains and reports for fixed nonces.
They do not contain private keys, cloud credentials, host access details or
captured authorization tokens. Tests never persist returned attestation JWTs.

`tdx_gpu_binding_v1.json` is an independently generated synthetic protocol
vector, not hardware evidence. Its identical copies in guest-components test
Rust/Go/Trustee encoding compatibility.
