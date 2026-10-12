# Trustee Helm Chart

## Multi-replica shared storage

Set `sharedStorage.enabled=true` to move authoritative mutable state from
writable pod volumes to MySQL. The chart reads Rust-service and Gateway
database credentials from an existing Secret, mounts pre-created AS and TPM
PCA keys read-only, and removes KBS/Gateway PVC templates and the RVPS
`emptyDir` state volume.

See [Trustee shared storage and multi-replica deployment](../docs/shared-storage.md)
for required Secret keys, values, backend compatibility and migration steps.

## Aliyun KMS Resource Backend

KBS can use Aliyun KMS generic secrets as the resource backend when the KBS image
is built with the `aliyun` feature.

Set `kbs.aliyunKms.enabled=true` and choose one authentication mode:

- AAP client key: set `clientKey`, `kmsInstanceId`, `password`, and `certPem`.
- AccessKey: set `regionId` and inject `ALIYUN_KMS_ACCESS_KEY_ID` and
  `ALIYUN_KMS_ACCESS_KEY_SECRET` through the pod environment. The recommended
  Helm path is to set `accessKeyExistingSecret` so the credentials come from an
  existing Kubernetes Secret.

For private cloud deployments, also set `endpoint` to the KMS intranet endpoint
provided by the private cloud KMS owner. If the endpoint uses a private CA, set
`certPem` to the CA certificate. `insecureSkipTlsVerify=true` is only intended
for temporary test environments where the certificate chain cannot yet be
trusted.

Example:

```yaml
kbs:
  aliyunKms:
    enabled: true
    regionId: "cn-test"
    endpoint: "kms-intranet.cn-test.example.com"
    certPem: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
    accessKeyExistingSecret: "aliyun-kms-credential"
    accessKeyIdSecretKey: "access_key_id"
    accessKeySecretSecretKey: "access_key_secret"
    insecureSkipTlsVerify: false
```

Create the referenced secret before installing or upgrading the chart:

```shell
kubectl create secret generic aliyun-kms-credential \
  --from-literal=access_key_id='LTAI...' \
  --from-literal=access_key_secret='secret...'
```

The old `kmsIntanceId` value key is still accepted for compatibility, but new
deployments should use `kmsInstanceId`.
