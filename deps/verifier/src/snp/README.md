# SNP crypto backends

`snp-verifier` keeps the native OpenSSL backend. `snp-rustcrypto` uses
RustCrypto RSA-PSS/SHA-384 for AMD endorsement certificates and ECDSA P-384
for report signatures, sharing the same evidence parser and SNP checks.
It also works on `wasm32-unknown-unknown` without OpenSSL or a filesystem.

Browser evidence must include its AMD-signed VCEK or VLEK in `cert_chain`.
There is no browser KDS or filesystem fallback. Supplying public collateral
does not authorize it: the verifier checks the embedded AMD roots, certificate
signature parameters, endorsement signature, report signature, hardware ID and
generation-specific reported TCB.

Both backends check VMPL, REPORT_DATA, HOST_DATA and SVSM binding. The signed
`init_data`, `report_data` and `chip_id` claims are exported for EAR appraisal
and transport-key binding; the existing base64 measurement encoding is retained.
Applications must additionally require their expected launch measurement,
native workload policy hash, non-debug/non-migratable policy and TCB floor.

Run the common vectors and negative binding tests with:

```sh
cargo test -p verifier --no-default-features --features snp-rustcrypto snp:: --lib
```
