# AS Signer Transparency 工具

`as-signer-transparency` 用于为 Trustee Attestation Service 生成 JWT signer 密钥、X.509 自签名证书，并将证书与本地 AA evidence、Rekor v2 透明日志条目绑定，最终生成 `signer_transparency.json` 供 AS 签发 token 时写入 `signer_transparency` claim。

## 依赖

- bash
- coreutils: `base64`、`date`、`sha256sum`
- `curl`
- `jq`
- `openssl`
- Python 3
- 可访问的本地 `trustiflux-api-server`，默认地址为 `http://127.0.0.1:8006`
- 可访问的 Rekor v2 服务，默认地址为 `https://log2025-1.rekor.sigstore.dev`

## 使用方法

```bash
./as-signer-transparency --config /path/to/as-config.json
```

常用参数:

- `--config`: Trustee AS JSON 配置文件路径，必填。
- `--signer-dir`: signer 材料目录，默认 `/run/trustee/attestation-service/signer`。
- `--api-server-url`: trustiflux-api-server 地址，默认 `http://127.0.0.1:8006`。
- `--rekor-url`: Rekor v2 地址，默认 `https://log2025-1.rekor.sigstore.dev`。
- `--cert-days`: 自签名证书有效期，默认 `365` 天。
- `--cert-url`: 可选，写入 AS 配置的 `signer.cert_url`。
- `--force-renew`: 强制重新生成 signer key 和证书。

工具会读取 `.attestation_token_broker.type`:

- `Ear`: 生成 P-256 EC 私钥和证书，匹配 AS 的 `ES256` 签发逻辑。
- `Simple`/`OIDC`: 生成 RSA-2048 私钥和证书，匹配 AS 的 `RS384`/`RS256` 签发逻辑。

## 输出文件

默认输出目录为 `/run/trustee/attestation-service/signer`:

```text
signer.key                 # AS JWT signer 私钥
signer.crt                 # AS JWT signer 自签名 X.509 证书
signer_evidence.json       # 以证书 DER SHA-256 为 runtime_data 获取的 AA evidence
signer_binding.json        # 证书 + evidence 绑定 payload
rekor_request_v2.json      # 提交 Rekor v2 的 dsseRequestV002 请求
rekor_entry_v2.json        # Rekor v2 返回的 rekorEntryV2
signer_transparency.json   # AS token claim 使用的透明可信材料
```

`signer.key` 和 `signer.crt` 已存在时，工具会检查证书是否过期以及证书公钥是否与私钥匹配。未过期且匹配时复用；过期、不匹配或指定 `--force-renew` 时会清理并重新生成。

## AS 配置变更

工具会就地更新 AS 配置中的 `attestation_token_broker.signer`:

```json
{
  "attestation_token_broker": {
    "type": "Ear",
    "signer": {
      "key_path": "/run/trustee/attestation-service/signer/signer.key",
      "cert_path": "/run/trustee/attestation-service/signer/signer.crt"
    }
  }
}
```

配置更新后需要重启 AS，使新的 signer key/cert 和 `signer_transparency.json` 在后续签发 token 时生效。

## 示例

```bash
sudo ./as-signer-transparency \
  --config /etc/trustee/attestation-service/as-config.json \
  --api-server-url http://127.0.0.1:8006 \
  --rekor-url https://log2025-1.rekor.sigstore.dev
```

完成后可以解码 AS 签发的 JWT payload，检查是否包含 `signer_transparency` 字段。
