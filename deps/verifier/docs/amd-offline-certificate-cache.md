# Offline AMD VCEK store

The SNP verifier normally obtains a VCEK from the evidence or AMD KDS. For
air-gapped deployments, pre-provision the public VCEK in a local store. The
lookup order is:

1. VCEK embedded in the evidence
2. TCB-specific file in the offline store
3. Legacy `vcek.der` in the offline store
4. AMD KDS

The default store root is:

```text
/opt/confidential-containers/attestation-service/kds-store
```

Set `TRUSTEE_SNP_VCEK_STORE` to use another root. Under that root, use this
layout:

```text
vcek/<lowercase-hardware-id>/
├── bl<BL>_tee<TEE>_snp<SNP>_ucode<UCODE>[_fmc<FMC>]_vcek.der
└── vcek.der
```

Each TCB component is decimal and zero-padded to two digits. Turin includes the
FMC suffix and uses the first 8 bytes of `CHIP_ID` as its hardware ID; earlier
generations use all 64 bytes. The TCB-specific file is recommended because a
firmware update can require a different VCEK for the same physical processor.

For example:

```bash
export TRUSTEE_SNP_VCEK_STORE=/srv/trustee/kds-store
install -D -m 0644 vcek.der \
  "$TRUSTEE_SNP_VCEK_STORE/vcek/<hardware-id>/bl00_tee00_snp00_ucode37_fmc00_vcek.der"
```

VCEKs are public endorsement certificates. Obtain them from AMD KDS on a
networked system, then transfer them through the deployment's approved artifact
path. Refresh the store after adding hardware or updating platform firmware.
