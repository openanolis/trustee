# RV Release Manifest 生成与上链工具

本目录包含脚本 `slsa-generator`，用于为制品生成 JCS 规范化的 `application/vnd.trustee.rv.release+json` RV release manifest，封装为 DSSE 后上传到 Rekor（v1/v2），并可将 release manifest bundle 上传到指定存储地址（首期支持 OCI）。

## 依赖

- bash
- coreutils: `sha256sum`
- cryptpilot-verity: `cryptpilot-verity`
- `uki` 类型额外需要: Python 3（调用同目录下的 `parse_uki_digest.py`）
- `jq`
- `curl`
- `openssl`

版本说明（已验证环境）:

- `openssl`: 3.x

## 使用方法

进入 `tools/slsa` 目录后运行:

```
./slsa-generator --artifact-type <type> --artifact <path> --artifact-id <id> \
  --artifact-version <version> --sign-key <key> [--measurement-name <name>] [更多可选参数]
```

参数说明:

- `--artifact-type`: 制品类型，支持 `binary`、`model-dir` 或 `uki`
- `--artifact`: 制品输入
  - `binary`: 文件路径
  - `model-dir`: 目录路径
  - `uki`: UKI 参考值 JSON **文件路径**（仅支持文件，不支持内联 JSON 字符串）
- `--artifact-id`: 制品自定义ID
- `--artifact-version`: 制品版本
- `--sign-key`: 用于签名 release manifest DSSE 的 PEM 私钥路径
- `--measurement-name`: 可选，release manifest `measurements` 中的名称；省略时使用 `artifact-id`。该名称允许完全自定义，消费侧按同名 `id` 提取。
- `--rekor-url`: Rekor 地址（默认 `https://rekor.sigstore.dev`）
- `--rekor-api-version`: Rekor API 主版本，`1` 或 `2`（默认 `1`）
- `--rekor-v2-key-details`: Rekor v2 verifier key details（默认 `PKIX_ECDSA_P256_SHA_256`）
- `--provenance-store-protocol`: provenance 存储协议（当前支持 `oci`）
- `--provenance-store-uri`: provenance 存储地址（如 `oci://127.0.0.1:5000/ns/repo:tag`）
- `--provenance-store-artifact`: 上传到存储的对象类型（`bundle`、`payload` 或 `dsse`，默认 `bundle`）

运行完成后会在当前目录生成输出目录，例如:

```
./slsa-output-<artifact-id>-<timestamp>/
  ├── release_payload.json
  ├── release.dsse.json
  ├── rekor-v1-entry.json / rekor-v2-entry.json
  └── release-manifest.trustee-bundle.json
```

各文件说明:

- `release_payload.json`: JCS 规范化后的 release manifest payload
- `release.dsse.json`: DSSE envelope（`payloadType=application/vnd.trustee.rv.release+json`）
- `rekor-v2-entry.json`: 上传到 Rekor v2 返回的透明日志条目（v2 模式下生成）
- `release-manifest.trustee-bundle.json`: 供 RVPS 消费的标准化组合元数据（`releasePayload` + `dsseEnvelope` + 可选 `rekorEntryV1`/`rekorEntryV2`）

## 生成签名密钥

使用 OpenSSL 生成一对 P-256 PEM 密钥:

```
openssl ecparam -name prime256v1 -genkey -noout -out rv-release.key
openssl pkey -in rv-release.key -pubout -out rv-release.pub
```

## 示例

```
./slsa-generator --artifact-type binary --artifact /path/to/app.bin \
  --artifact-id app-binary --artifact-version 1.0.0 \
  --measurement-name cvm_container_proxy \
  --sign-key /path/to/rv-release.key \
  --rekor-url https://log2025-1.rekor.sigstore.dev --rekor-api-version 2 \
  --provenance-store-protocol oci \
  --provenance-store-uri oci://127.0.0.1:5000/trustee/provenance:app-binary-1.0.0 \
  --provenance-store-artifact bundle
```

```
./slsa-generator --artifact-type model-dir --artifact /path/to/model \
  --artifact-id modelA --artifact-version 2024-02-01 --sign-key /path/to/rv-release.key
```

UKI 示例（`--artifact` 指向 JSON 文件）:

```json
{
  "measurement.uki.SHA-384": [
    "aa1c6086ed05f3c9ebe767301914ea23aeff9aa1deb090845305e730ebb7573db7e9000b7d30bd3583c4a4e3a618570f"
  ]
}
```

```bash
./slsa-generator --artifact-type uki --artifact /path/to/uki.json \
  --artifact-id uki-image --artifact-version 1.0.0 --sign-key /path/to/rv-release.key
```

## 说明

- Rekor v1 公共实例 URL: `https://rekor.sigstore.dev`
- Rekor v2 需要使用 `/api/v2/log/entries`，脚本在 `--rekor-api-version 2` 时走 v2 上传逻辑。
- `model-dir` 的摘要通过 `cryptpilot-verity dump <model-dir-path> --print-root-hash` 获取。
- Rekor v1 模式下脚本直接提交 `kind=dsse` 的 `/api/v1/log/entries` 请求；Rekor 响应中的 `payloadHash` 与 `release_payload.json` 的 SHA256 一致。
- `uki` 会从 `measurement.uki.<algorithm>` 提取摘要算法和值，`<algorithm>` 兼容 `sha256`/`sha384`（大小写及连字符写法均可，例如 `SHA-256`、`SHA-384`）。解析逻辑见 `parse_uki_digest.py`。
- 上传到 Rekor 后，可用 Gateway/KBS 的 `set_reference_value_list` 或本地 `attestation-challenge-client set-reference-value-list --rv-list <json>` 按 `rv-release-manifest` 类型从 bundle 中提取 `measurements` 并写入 RVPS。每项可选字段 `rv_name` 可覆盖默认参考值名（新格式默认使用 measurement 名称）。
- v2 模式下脚本使用 HTTP API 直接提交 `dsseRequestV002`。
