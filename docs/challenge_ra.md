# 挑战模式远程证明（Challenge RA）使用指南

本工具 `attestation-challenge-client` 是一个命令行客户端，用来：
- 向目标虚机中的 `api-server-rest` 获取 TEE 证明材料（evidence）
- 查询rekor透明日志以获取度量基线参考值，并设置到本地以备使用
- 对 TEE 证明材料（evidence）进行验证，生成 EAR 令牌

## 前置条件
1. 目标TEE里已运行 `attestation-agent` 和 `trustiflux-api-server`，并暴露远端访问接口：
   - 默认监听 `0.0.0.0:8006`
   - 若需从远端调用 `GET /aa/evidence`，需在 `trustiflux-api-server.toml` 中设置 `allow_remote_get_evidence = true`
   - 若需从远端调用 `POST /cdh/resource-injection/...`，需设置 `allow_remote_resource_injection = true`
2. 了解目标 TEE 类型（如 `tdx`、`sgx`、`snp` 等），验证阶段需要显式指定。
3. (可选) runtime data（通常是挑战值/nonce 或自定义 report data）由调用者自行提供，并在获取证据与验证时保持一致。

## 获取证据
```bash
attestation-challenge-client get-evidence \
  --aa-url http://<host>:8006 \
  --runtime-data "<runtime-string>" \
  --output /tmp/evidence.json
```
- 当 `--aa-url` 指向远端 TEE 时，需要目标侧 `api-server-rest` 已开启 `allow_remote_get_evidence = true`
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

## 设置参考值
`attestation-challenge-client` 支持在本地调用内置 RVPS 注册参考值，常见场景是从可信来源（如rekor透明日志）上查询相应的参考值写入本地 RVPS，再执行 `verify`。

命令入口：
```bash
attestation-challenge-client set-reference-value --provenance-type <slsa|sample> [args...]
attestation-challenge-client set-reference-value-list --rv-list <rv-list.json>
```

### SLSA 模式 (rekor透明日志)

#### 方式一（经典模式）

这种方式只支持rekor v1

```bash
attestation-challenge-client set-reference-value \
  --provenance-type slsa \
  --artifact-type <artifact_type> \
  --artifact-name <artifact_name> \
  [--rekor-url https://rekor.sigstore.dev]
```
- 逻辑：对 `artifact-name` 做 sha256 作为索引，访问rekor透明日志查询相应条目，过滤并提取 SLSA provenance (包含度量参考值)，组装为 RVPS 能识别的 message 后注册。
- `--rekor-url` 可选，默认 `https://rekor.sigstore.dev`。

#### 方式二（批量模式）

这种方式能够支持rekor v2

```bash
attestation-challenge-client set-reference-value-list --rv-list /path/to/rv-list.json
```

- 逻辑：读取 JSON 文件（顶层字段 `rv_list`，格式与 Gateway/KBS 的 `POST .../set_reference_value_list` 请求体一致），调用内置 RVPS 的 `set_reference_value_list`：按每项的 `id`+`version` 及其 `provenance_info.rekor_url` 从 Rekor 拉取 SLSA，解析 digest 后写入参考值。
- 每项可选 `rv_name`：若指定则作为 RVPS 中的参考值名称；省略时默认 `measurement.<type>.<id>`（与网关 API 行为一致）。


### Sample 模式
```bash
attestation-challenge-client set-reference-value \
  --provenance-type sample \
  --payload /path/to/payload.json
```
- 逻辑：直接读取 `payload.json`（需符合 RVPS sample extractor 格式），封装为 RVPS message 后注册。

注册成功后，内置 RVPS 会持久化到 `/var/lib/attestation/reference_values.json`（见下述环境变量可覆盖路径），后续 `verify` 会使用这些参考值。

可打开 reference value 文件以审计已经设置的参考值：
```shell
cat /var/lib/attestation/reference_values.json | jq
```

工作目录：默认使用 `/var/lib/attestation` 存放 `reference_values.json` 与策略目录。无 root 权限或本地测试时，可设置环境变量 `ATTESTATION_CHALLENGE_CLIENT_WORK_DIR` 指向可写目录（需提前存在或允许创建子目录）；`get-evidence` / `verify` / `inject-resource` / `set-reference-value` / `set-reference-value-list` 均使用该目录。


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
3. （可选）先向本地 RVPS 注册参考值：
   - SLSA（单条 Rekor 索引串）：`attestation-challenge-client set-reference-value --provenance-type slsa --artifact-type <type> --artifact-name <name> [--rekor-url ...]`
   - Sample：`attestation-challenge-client set-reference-value --provenance-type sample --payload /path/to/payload.json`
   - 批量（与 `set_reference_value_list` 请求体一致）：`attestation-challenge-client set-reference-value-list --rv-list /path/to/rv-list.json`
4. 在验证端运行 `verify`，指定相同的 runtime data 与正确的 `--tee`，得到 EAR 令牌
5. 如需查看令牌内容，加 `--claims` 直接展示 payload

## 注意事项
- 证据文件应为 JSON 文本；如果内容格式异常，验证会直接返回错误。
- 生成的策略目录与 RVPS 文件如不存在会自动创建，但策略仍依赖默认 `default` rego（已内置）。
- 若需要自定义策略或参考值，可在 `/var/lib/attestation` 下按需要提前准备。

## 基于挑战证明的机密资源注入

`attestation-challenge-client` 新增了 `inject-resource` 子命令，用于从验证端将机密资源注入到 TEE 内 CDH。

远程调用该流程时，需要目标侧 `api-server-rest` 开启 `allow_remote_resource_injection = true`。该开关只影响 `POST /cdh/resource-injection/...`，`GET /cdh/resource/...` 仍然只允许本地回环地址访问。

### 一体化命令

```bash
attestation-challenge-client inject-resource \
  --api-url http://<host>:8006 \
  --resource-path default/key/1 \
  --resource-file /path/to/plaintext.bin \
  --tee tdx \
  --policy default
```

可选参数：
- `--nonce`：显式指定挑战 nonce；不指定则自动随机生成
- `--init-data-digest` / `--init-data-toml`：用于验证时绑定 init data
- `--policy`：可重复，默认 `default`

### 内部流程（命令自动执行）

1. 调用 `POST /cdh/resource-injection/prepare/{repository}/{type}/{tag}`，传入 nonce
2. 获取 `session_id`、`tee_pubkey`、`evidence`
3. 在验证端本地执行 evidence 验证（runtime_data 固定为 `nonce + tee_pubkey`，并固定使用 `sha384` 哈希）
4. 用 `tee_pubkey` 加密资源（KBS 兼容加密结构）
5. 调用 `POST /cdh/resource-injection/commit/{repository}/{type}/{tag}` 提交密文
6. CDH 在 TEE 内解密并写入 `/run/confidential-containers/cdh/<repository>/<type>/<tag>`

