# AS证书透明可信

## 背景

Trustee Attestation Service（AS）签发 JWT attestation token 时，可以在 token header 的 JWK 中携带 signer 的 X.509 证书链。客户端能够用该证书验证 token 签名，但还需要知道证书本身是否来自可信的机密计算环境，以及证书和该环境证明是否被公开、可审计地记录。

AS 证书透明可信功能为 AS signer 增加一条可验证链路:

1. 为 AS JWT token 生成 signer 私钥和自签名 X.509 证书。
2. 计算证书 DER 的 SHA-256 哈希，并把该哈希作为 `runtime_data` 访问本地 `trustiflux-api-server` 的 `GET /aa/evidence` API。
3. 将证书和 AA evidence 打包成 `signer_binding.json`，证明 evidence 的 report data 绑定到了证书哈希。
4. 将 `signer_binding.json` 作为 DSSE payload 提交到 Rekor v2 透明日志。
5. 将 payload、payload 元数据和 Rekor v2 返回的 `rekorEntryV2` 打包为 `signer_transparency.json`。
6. AS 后续签发 JWT token 时，尝试读取 `signer_transparency.json`，并把完整内容写入可选 claim `signer_transparency`。

该功能不改变 AS 原有 token 验签方式；它是在已有签名证书之上增加透明日志和 TEE evidence 绑定材料。

## 组件

- 生成工具: `tools/as-signer-transparency/as-signer-transparency`
- 默认 signer 目录: `/run/trustee/attestation-service/signer`
- AS claim 文件: `/run/trustee/attestation-service/signer/signer_transparency.json`
- AA evidence API: `GET http://127.0.0.1:8006/aa/evidence?runtime_data=<cert_hash>`
- Rekor v2 API: `POST <rekor-url>/api/v2/log/entries`

## 数据格式

### signer_binding.json

`signer_binding.json` 是提交 Rekor v2 的 payload，格式如下:

```json
{
  "schema_version": "trustee.as.signer-binding/v1",
  "generated_at": "2026-04-27T07:00:00Z",
  "signer_certificate": {
    "path": "/run/trustee/attestation-service/signer/signer.crt",
    "pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "der_sha256": "<sha256-of-x509-der>",
    "not_after": "Apr 27 07:00:00 2027 GMT"
  },
  "evidence_binding": {
    "api_server_url": "http://127.0.0.1:8006",
    "report_data": "<sha256-of-x509-der>",
    "report_data_algorithm": "sha256(x509 DER)",
    "runtime_data_encoding": "hex",
    "evidence": {}
  }
}
```

`evidence` 通常是 AA 返回的 JSON evidence。如果返回体不是 JSON，工具会用 `{ "encoding": "base64", "data": "..." }` 保存原始字节。

### signer_transparency.json

`signer_transparency.json` 是写入 JWT claim 的内容，格式如下:

```json
{
  "schema_version": "trustee.as.signer-transparency/v1",
  "generated_at": "2026-04-27T07:00:10Z",
  "payload": {},
  "payload_metadata": {
    "path": "/run/trustee/attestation-service/signer/signer_binding.json",
    "media_type": "application/vnd.trustee.as.signer-binding+json",
    "digest": {
      "sha256": "<sha256-of-signer_binding-json>"
    },
    "size": 1234
  },
  "rekor": {
    "url": "https://log2025-1.rekor.sigstore.dev",
    "api_version": "v2",
    "request_type": "dsseRequestV002",
    "key_details": "PKIX_ECDSA_P256_SHA_256",
    "rekorEntryV2": {}
  }
}
```

其中 `payload` 是完整的 `signer_binding.json` 内容；`rekor.rekorEntryV2` 是 Rekor v2 返回的透明日志条目，包含 `logIndex`、`inclusionProof`、`checkpoint` 等字段，具体字段由 Rekor v2 服务返回为准。

## JWT claim

AS 在签发 token 时会尝试读取:

```text
/run/trustee/attestation-service/signer/signer_transparency.json
```

文件存在且为合法 JSON 时，AS 在 JWT payload 中加入:

```json
{
  "signer_transparency": {
    "...": "..."
  }
}
```

文件不存在、不可读或 JSON 非法时，AS 会跳过该 claim，token 签发继续进行。这个字段是可选字段，不影响已有客户端。

## 使用流程

1. 启动 `attestation-agent` 和本地 `trustiflux-api-server`，确保 `GET /aa/evidence` 可用。
2. 运行工具生成 signer 和透明可信材料:

```bash
sudo tools/as-signer-transparency/as-signer-transparency \
  --config /etc/trustee/attestation-service/as-config.json \
  --api-server-url http://127.0.0.1:8006 \
  --rekor-url https://log2025-1.rekor.sigstore.dev
```

3. 重启 AS，使配置中的 `attestation_token_broker.signer` 生效。
4. 请求 AS 签发 token。
5. 解码 JWT payload，检查 `signer_transparency` claim。
6. 验证方可按以下逻辑验证:

- 用 token header 中的 `jwk.x5c` 或 AS 证书接口拿到 signer 证书，并验证 token 签名。
- 计算证书 DER SHA-256，确认等于 `signer_transparency.payload.signer_certificate.der_sha256`。
- 验证 AA evidence 中的 report data 与该证书哈希一致。
- 计算 `signer_transparency.payload` 的 SHA-256，确认等于 `payload_metadata.digest.sha256`。
- 用 Rekor v2 返回的 `rekorEntryV2` 和对应公钥验证 DSSE payload 已进入透明日志。

## 注意事项

- 默认 `Ear` token 使用 P-256 EC signer；`Simple` 和 `OIDC` token 使用 RSA-2048 signer。工具会根据 AS 配置中的 `attestation_token_broker.type` 自动选择。
- `signer.key` 是 AS token 签名私钥，应限制权限并只允许 AS 运行用户读取。
- 证书未过期且公钥与私钥匹配时，工具会复用已有 signer；过期、不匹配或使用 `--force-renew` 时会重新生成。
- `signer_transparency` claim 可能较大，尤其是 TEE evidence 和 Rekor inclusion proof 较长时。部署方应确认下游 token 传输路径允许相应大小。
