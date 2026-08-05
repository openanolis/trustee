# AMD SEV-SNP appraisal

Trustee verifies the SNP report signature, endorsement chain, VCEK TCB
extensions, VMPL, and `REPORT_DATA` before evaluating an attestation policy.
The default EAR and OIDC policies also require Debug and Migration Agent to be
disabled. Deployment-specific launch-measurement and platform-TCB allow-lists
are included as commented examples and are disabled by default, matching the
customization model used by the other platform branches.

## Reference values

When the relying party needs stricter appraisal, uncomment the corresponding
checks in the default policy (or, preferably, install a deployment-owned policy)
and register arrays of accepted string values under these RVPS keys:

| Key | SNP claim |
| --- | --- |
| `snp.measurement` | Initial guest launch measurement (Base64) |
| `snp.reported_tcb_bootloader` | Bootloader security patch level |
| `snp.reported_tcb_tee` | TEE security patch level |
| `snp.reported_tcb_snp` | SNP firmware security patch level |
| `snp.reported_tcb_microcode` | CPU microcode security patch level |
| `snp.reported_tcb_fmc` | Turin+ FMC security patch level |

Enable the FMC check only for Turin and later evidence that contains the claim.
Once a check is enabled, a missing or mismatched reference value prevents an
affirming EAR appraisal (producing `warning` or `contraindicated`, depending on
the failed trust claim) and causes an OIDC policy rejection.

A sample RVPS message is:

```json
{
  "version": "0.1.0",
  "type": "sample",
  "payload": "<base64-of-reference-value-json>"
}
```

The decoded payload has this shape:

```json
{
  "snp.measurement": ["<base64-launch-measurement>"],
  "snp.reported_tcb_bootloader": ["0"],
  "snp.reported_tcb_tee": ["0"],
  "snp.reported_tcb_snp": ["0"],
  "snp.reported_tcb_microcode": ["37"],
  "snp.reported_tcb_fmc": ["0"]
}
```

## Scope

The SNP launch measurement authenticates initial guest state; it is not a
dynamic runtime or filesystem measurement. For plain SNP evidence, the default
EAR policy therefore reports no filesystem claim. Use SVSM/vTPM or another
measured-boot mechanism when the relying party requires boot-event or runtime
filesystem appraisal.
