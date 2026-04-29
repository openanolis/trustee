# Trustee Helm Chart

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
