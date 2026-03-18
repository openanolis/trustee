# SLSA Provenance 生成与上链工具

本目录包含脚本 `slsa-generator`，用于为制品生成最简SLSA provenance（in-toto Statement），完成签名并上传到 Rekor（v1/v2），并可将 provenance 元数据上传到指定存储地址（首期支持 OCI）。

## 依赖

- bash
- coreutils: `sha256sum`
- cryptpilot-verity: `cryptpilot-verity`
- sigstore: `cosign`
- sigstore: `rekor-cli`
- `uki` 类型额外需要: Python 3（调用同目录下的 `parse_uki_digest.py`）
- `jq`
- `curl`
- `openssl`

版本说明（已验证环境）:

- `cosign`: `v3.0.5`
- `rekor-cli`: `v1.5.1`

## 使用方法

进入 `tools/slsa` 目录后运行:

```
./slsa-generator --artifact-type <type> --artifact <path> --artifact-id <id> \
  --artifact-version <version> --sign-key <key> [更多可选参数]
```

参数说明:

- `--artifact-type`: 制品类型，支持 `binary`、`model-dir` 或 `uki`
- `--artifact`: 制品输入
  - `binary`: 文件路径
  - `model-dir`: 目录路径
  - `uki`: UKI 参考值 JSON **文件路径**（仅支持文件，不支持内联 JSON 字符串）
- `--artifact-id`: 制品自定义ID
- `--artifact-version`: 制品版本
- `--sign-key`: 用于签名SLSA provenance的私钥路径(cosign生成)
- `--rekor-url`: Rekor 地址（默认 `https://rekor.sigstore.dev`）
- `--rekor-api-version`: Rekor API 主版本，`1` 或 `2`（默认 `1`）
- `--rekor-v2-key-details`: Rekor v2 verifier key details（默认 `PKIX_ECDSA_P256_SHA_256`）
- `--provenance-store-protocol`: provenance 存储协议（当前支持 `oci`）
- `--provenance-store-uri`: provenance 存储地址（如 `oci://127.0.0.1:5000/ns/repo:tag`）
- `--provenance-store-artifact`: 上传到存储的对象类型（`bundle` 或 `provenance`，默认 `bundle`）

运行完成后会在当前目录生成输出目录，例如:

```
./slsa-output-<artifact-id>-<timestamp>/
  ├── statement.json
  ├── statement.attestation.json
  └── statement.dsse.json
  ├── statement.intoto.jsonl
  ├── rekor-v1-upload.txt / rekor-v2-entry.json
  └── provenance.trustee-bundle.json
```

各文件说明:

- `statement.json`: 原始 in-toto Statement（SLSA provenance）
- `statement.attestation.json`: cosign 输出的 attestation 产物
- `statement.dsse.json`: DSSE envelope（包含 `payload`、`payloadType`、`signatures`）
- `statement.intoto.jsonl`: 单条 DSSE 的 JSONL 形式
- `rekor-v2-entry.json`: 上传到 Rekor v2 返回的透明日志条目（v2 模式下生成）
- `provenance.trustee-bundle.json`: 供 RVPS 新链路消费的标准化组合元数据（`sourceBundle` + `dsseEnvelope` + 可选 `rekorEntryV2`）

## 生成签名密钥

使用 cosign 生成一对密钥:

```
cosign generate-key-pair
```

默认生成:

- `cosign.key` (私钥，供 `sign-key` 参数使用)
- `cosign.pub` (公钥，供上传Rekor使用)

也可以指定输出路径:

```
cosign generate-key-pair --output-key-prefix /path/to/mykey
```

这将生成 `/path/to/mykey.key` 与 `/path/to/mykey.pub`。

## 示例

```
./slsa-generator --artifact-type binary --artifact /path/to/app.bin \
  --artifact-id app-binary --artifact-version 1.0.0 --sign-key /path/to/cosign.key \
  --rekor-url https://log2025-1.rekor.sigstore.dev --rekor-api-version 2 \
  --provenance-store-protocol oci \
  --provenance-store-uri oci://127.0.0.1:5000/trustee/provenance:app-binary-1.0.0 \
  --provenance-store-artifact bundle
```

```
./slsa-generator --artifact-type model-dir --artifact /path/to/model \
  --artifact-id modelA --artifact-version 2024-02-01 --sign-key /path/to/cosign.key
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
  --artifact-id uki-image --artifact-version 1.0.0 --sign-key /path/to/cosign.key
```

## 说明

- Rekor v1 公共实例 URL: `https://rekor.sigstore.dev`
- Rekor v2 需要使用 `/api/v2/log/entries`，脚本在 `--rekor-api-version 2` 时走 v2 上传逻辑。
- `model-dir` 的摘要通过 `cryptpilot-verity dump <model-dir-path> --print-root-hash` 获取。
- 脚本使用 `rekor-cli upload --type intoto`，上传对象为 `statement.dsse.json`（DSSE envelope），而不是原始 `statement.json`。
- `uki` 会从 `measurement.uki.<algorithm>` 提取摘要算法和值，`<algorithm>` 兼容 `sha256`/`sha384`（大小写及连字符写法均可，例如 `SHA-256`、`SHA-384`）。解析逻辑见 `parse_uki_digest.py`。
- 上传到 Rekor 后，可用 Gateway/KBS 的 `set_reference_value_list` 或本地 `attestation-challenge-client set-reference-value-list --rv-list <json>` 按 `rv_list`（含每项 `provenance_info.rekor_url`）从 Rekor 拉取并写入 RVPS。每项可选字段 `rv_name` 可覆盖默认参考值名 `measurement.<type>.<id>`（详见 `trustee-gateway/trustee_gateway_api.md` 与 `docs/challenge_ra.md`）。
- v1 模式下脚本使用 `rekor-cli upload --type intoto`。
- v2 模式下脚本使用 HTTP API 直接提交 `dsseRequestV002`。
