# 挑战模式远程证明（Challenge RA）使用指南

本工具 `attestation-challenge-client` 是一个命令行客户端，用来：
- 向目标虚机中的 `api-server-rest` 获取 TEE 证明材料（evidence）
- 使用本地的 attestation-service 库进行验证，生成 EAR 令牌

与服务化的 AS 不同，本工具完全使用内置默认配置，不读取外部配置文件。

## 默认行为与目录
- 工作目录：`/var/lib/attestation`
- RVPS：内置模式，存储为 LocalJson（路径：`/var/lib/attestation/reference_values.json`）
- Token broker：EAR 格式，策略目录：`/var/lib/attestation/token/ear/policies`
- 默认策略 ID：`default`

## 前置条件
1. 目标TEE里已运行 `api-server-rest`，并暴露 GET `/aa/evidence?runtime_data=...`
   - 默认监听 `127.0.0.1:8006`，如需远程访问请按需改为 0.0.0.0 或做端口转发
   - 该接口仅允许 loopback 访问，远程访问需通过代理/转发保证来源为本地回环
2. 了解目标 TEE 类型（如 `tdx`、`sgx`、`snp` 等），验证阶段需要显式指定。
3. runtime data（通常是挑战值/nonce 或自定义 report data）由调用者自行提供，并在获取证据与验证时保持一致。

## 获取证据
```bash
attestation-challenge-client get-evidence \
  --aa-url https://<host>:8006 \
  --runtime-data "<runtime-string>" \
  --output /tmp/evidence.json
```
- `--runtime-data`：直接传字符串（UTF-8）
- `--runtime-data-file`：从文件读取字符串（UTF-8），与 `--runtime-data` 互斥
- 若未指定 runtime data，将使用空字符串
- 不带 `--output` 时，证据 JSON 将直接打印到 stdout

示例：
```bash
attestation-challenge-client get-evidence \
  --aa-url http://127.0.0.1:8006 \
  --runtime-data "$(cat challenge_token.txt)" \
  --output /tmp/evidence.json
```

## 验证证据并生成 EAR 令牌
```bash
attestation-challenge-client verify \
  --evidence /tmp/evidence.json \
  --tee tdx \
  --runtime-raw "$(cat challenge_token.txt)" \
  --policy default \
  --claims
```
- `--tee`：必填，支持 `tdx`、`sgx`、`snp`、`csv`、`azsnpvtpm`、`aztdxvtpm`、`sample`、`sampledevice`、`system`、`se`、`tpm`、`hygondcu`
- runtime data 互斥选项：
  - `--runtime-raw <STRING>`：以 UTF-8 字节作为 runtime data
  - `--runtime-raw-file <PATH>`：从文件读取原始字节
  - `--runtime-json <JSON>` / `--runtime-json-file <PATH>`：结构化 JSON runtime data
- `--runtime-hash-alg`：哈希算法，默认 `sha384`（可选 `sha256`/`sha512`）
- init data 互斥选项：
  - `--init-data-digest <HEX>`：16 进制编码的摘要
  - `--init-data-toml <PATH>`：TOML 格式的 init data
- `--policy`：可重复，默认 `default`
- `--claims`：除输出 JWT 外，再解析并格式化打印 payload（便于快速阅读）

输出：
- 默认打印 EAR JWT
- 若加 `--claims`，随后会打印 payload 的 JSON（不再校验签名，只做展示）

## 典型流程
1. 在机密虚拟机TEE内启动 `api-server-rest`（确保可通过本地或端口转发访问）
2. 准备挑战值/nonce，调用 `get-evidence` 获取 `evidence.json`
3. 在验证端运行 `verify`，指定相同的 runtime data 与正确的 `--tee`，得到 EAR 令牌
4. 如需查看令牌内容，加 `--claims` 直接展示 payload

## 注意事项
- 证据文件应为 JSON 文本；如果内容格式异常，验证会直接返回错误。
- 生成的策略目录与 RVPS 文件如不存在会自动创建，但策略仍依赖默认 `default` rego（已内置）。
- 若需要自定义策略或参考值，可在 `/var/lib/attestation` 下按需要提前准备。

