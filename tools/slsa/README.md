# SLSA Provenance 生成与上链工具

本目录包含脚本 `slsa-generator`，用于为制品生成最简SLSA provenance（in-toto Statement），完成签名并上传到 Rekor 透明日志公共实例。

## 依赖

- bash
- coreutils: `sha256sum`
- cryptpilot-verity: `cryptpilot-verity`
- sigstore: `cosign`
- sigstore: `rekor-cli`

## 使用方法

进入 `tools/slsa` 目录后运行:

```
./slsa-generator --artifact-type <type> --artifact <path> --artifact-id <id> \
  --artifact-version <version> --sign-key <key>
```

参数说明:

- `--artifact-type`: 制品类型，支持 `binary` 或 `model-dir`
- `--artifact`: 制品路径(文件或目录)
- `--artifact-id`: 制品自定义ID
- `--artifact-version`: 制品版本
- `--sign-key`: 用于签名SLSA provenance的私钥路径(cosign生成)

运行完成后会在当前目录生成输出目录，例如:

```
./slsa-output-<artifact-id>-<timestamp>/
  ├── statement.json
  ├── statement.attestation.json
  └── statement.dsse.json
```

各文件说明:

- `statement.json`: 原始 in-toto Statement（SLSA provenance）
- `statement.attestation.json`: cosign 输出的 attestation 产物
- `statement.dsse.json`: DSSE envelope（包含 `payload`、`payloadType`、`signatures`），用于以 `intoto` 类型上传 Rekor

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
  --artifact-id app-binary --artifact-version 1.0.0 --sign-key /path/to/cosign.key
```

```
./slsa-generator --artifact-type model-dir --artifact /path/to/model \
  --artifact-id modelA --artifact-version 2024-02-01 --sign-key /path/to/cosign.key
```

## 说明

- Rekor 公共实例 URL: `https://rekor.sigstore.dev`
- `model-dir` 的摘要通过 `cryptpilot-verity dump <model-dir-path> --print-root-hash` 获取。
- 脚本使用 `rekor-cli upload --type intoto`，上传对象为 `statement.dsse.json`（DSSE envelope），而不是原始 `statement.json`。
