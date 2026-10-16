# Trustee Gateway API

本文对应当前 Gateway 路由，以及 [E2E API 清单](test/e2e/api-contract.json)。
以下路径均相对 Gateway 地址，例如 `http://127.0.0.1:8081`；`{id}` 等是需要替换的路径参数。
**客户端使用 `/api/...`。** Gateway 转发到 KBS 时移除 `/api`，转发到 RESTful AS 时移除 `/api/as` 或 `/api/attestation-service`。

## 认证和状态归属

- KBS 管理操作使用 `Authorization: Bearer <admin-jwt>`。管理员 JWT 使用 Ed25519/EdDSA 签名，KBS 通过 `admin.auth_public_key` 校验。`admin.insecure_api=true` 仅用于隔离测试，不应在生产启用。
- 资源读取使用 **证明结果 JWT**（同样使用 Bearer 头，但不是管理员 JWT），或 RCAR 证明完成后的 `kbs-session-id` Cookie。管理员 JWT 不能代替证明结果。
- AS 的两组别名完全等价。当前 RESTful AS（包括策略管理）、审计、健康、AA 实例和 Credential 接口未实现 Gateway 自身的用户鉴权。必须通过部署侧的 API 访问控制、网络隔离和 TLS 保护；尤其不能将策略管理及 Credential 接口直接暴露到不可信网络。
- 策略、参考值和资源的权威状态位于 KBS/AS/RVPS 对应存储中；Gateway **不再保存这些状态的副本**。Gateway 数据库只保存审计和 AA 心跳。
- 多副本部署的共享状态和稳定签名身份见 [共享存储配置说明](../docs/shared-storage.md)。本文的管理请求不会绕过后端的存储能力限制。

所有成功的管理写入通常返回 `200`、空响应体。Gateway 保留后端状态码和响应体，不把后端拒绝转换成成功。

## 1. KBS API

| 操作 | 接口 | 授权 / 请求 / 成功响应 |
| --- | --- | --- |
| 启动 RCAR 会话 | `POST /api/kbs/v0/auth` | 无 Bearer；JSON `version/tee/extra-params`；返回 Challenge 和 Cookie |
| 提交证据 | `POST /api/kbs/v0/attest` | 会话 Cookie；JSON `runtime-data/tee-evidence`；返回 `{"token":"<jwt>"}` |
| 设置证明策略 | `POST /api/kbs/v0/attestation-policy` | 管理员；JSON `policy_id/policy` |
| 获取证明策略 | `GET /api/kbs/v0/attestation-policy/{id}` | 管理员；返回 Base64URL 编码的策略字符串 |
| 列出证明策略 | `GET /api/kbs/v0/attestation-policies` | 管理员；返回 `{ "id": "policy-hash", ... }` |
| 删除证明策略 | `DELETE /api/kbs/v0/attestation-policy/{id}` | 管理员；不能删除默认策略 |
| 设置资源策略 | `POST /api/kbs/v0/resource-policy` | 管理员；JSON `{"policy":"<base64url>"}` |
| 获取资源策略 | `GET /api/kbs/v0/resource-policy` | 管理员；返回 Base64URL 策略字符串，不是原始 Rego |
| 读取资源 | `GET /api/kbs/v0/resource/{repository}/{type}/{tag}` | 证明 JWT 或已证明会话；通过资源策略后返回 JWE |
| 写入 / 更新资源 | `POST /api/kbs/v0/resource/{repository}/{type}/{tag}` | 管理员；原始资源字节或加密存储 Envelope |
| 删除资源 | `DELETE /api/kbs/v0/resource/{repository}/{type}/{tag}` | 管理员 |
| 获取资源加密公钥 | `GET /api/kbs/v0/resource/pubkey` | 管理员；加密存储后端返回 RSA 公钥 PEM |
| 热加载托管密钥 | `POST /api/kbs/v0/resource/reload` | 管理员；返回 `{"reloaded_keys":N}` |
| 重包资源 | `POST /api/kbs/v0/resource/rewrap` | 管理员；返回重包报告 |
| 轮转托管密钥 | `POST /api/kbs/v0/resource/rotate` | 管理员；返回新公钥及轮转报告 |
| 列出资源 | `GET /api/kbs/v0/resources` | 管理员；返回资源描述数组，不是带 `data/total` 的 Gateway 分页对象 |

### 1.1 RCAR 证明和资源获取

`auth` 请求示例（`sample` 仅用于测试，真实部署选择实际 TEE）：

```json
{"version":"0.4.0","tee":"sample","extra-params":""}
```

保存响应的 `kbs-session-id` Cookie，并将 Challenge 中的 `nonce`、客户端资源解密公钥绑定到证据中。提交的结构为：

```json
{
  "runtime-data": {
    "nonce": "<challenge.nonce>",
    "tee-pubkey": {"kty":"RSA","alg":"RSA-OAEP-256","n":"<base64url-modulus>","e":"AQAB"}
  },
  "tee-evidence": {
    "primary_evidence": {},
    "additional_evidence": ""
  }
}
```

`primary_evidence` 必须是实际采证结果，不能直接使用空对象。主证据的 report-data 绑定包含 `nonce`、`tee-pubkey` 和 `additional-evidence` 的规范化 JSON；具体算法和长度遵循对应 TEE/verifier。`additional_evidence` 是 JSON **字符串**，无附加证据时使用空字符串。可选 `init-data` 为 `{"format":"toml","body":"<raw-TOML-text>"}`。注意 KBS 顶层字段是连字符命名，不要与 RESTful AS 的 `runtime_data` 字段混用。

证明成功后可使用 Cookie 或返回的 JWT 读取资源：

```shell
curl "$GATEWAY/api/kbs/v0/resource/myrepo/key/mytag" \
  -H "Authorization: Bearer $ATTESTATION_JWT"
```

返回的是使用被证明客户端公钥加密的 JWE（`protected/encrypted_key/iv/ciphertext/tag`），**不是明文**，也不是存储 Envelope。客户端必须解包 CEK 并验证 AES-GCM 标签及 protected-header AAD。当前 RSA-OAEP-256 路径使用 AES-256-GCM。

证明会话重试成功后会返回原 token；这不是将新证据重新验证一次。多副本模式的会话共享依赖共享 session storage。JWT 中的 `exp` 仍然适用。

### 1.2 策略操作

`policy` 字段均使用 **Base64URL、不带 padding**，不要混用 `base64` 命令默认的 STANDARD 编码。

```json
{"policy_id":"my-policy","policy":"<base64url-no-padding-rego>"}
```

证明策略请求不需要旧文档中的 `type` 字段。资源策略请求只包含 `policy`，没有 `policy_id`：

```json
{"policy":"<base64url-no-padding-rego>"}
```

默认策略 ID 是 `default`。KBS 的证明策略操作实际访问其 AS 后端；Gateway 的 AS 别名操作访问所配置的 RESTful AS。要观察同一套策略，必须让两者使用同一个权威策略存储，不能仅假设其配置相同。

### 1.3 资源存储、密钥维护和轮转

资源名由 repository/type/tag 三段组成，支持字母、数字、下划线、连字符和符合后端规则的点号。列表响应示例：

```json
[{"repository_name":"myrepo","resource_type":"key","resource_tag":"mytag"}]
```

- `LocalFs`、`SharedStore` 通过资源 POST 保存原始字节，不支持 RSA 托管密钥维护。
- `EncryptedLocalFs`、`EncryptedDb` 支持客户端先获取 `pubkey`，再提交 Envelope。支持的算法与后端实现一致；推荐 `RSA-OAEP-256`。
- Envelope 的各二进制字段使用 **STANDARD Base64**；这与证明 token / JWE 的 Base64URL 不同。

```json
{
  "alg":"RSA-OAEP-256",
  "enc_key":"<RSA-wrapped-32-byte-CEK>",
  "iv":"<12-byte-IV>",
  "ciphertext":"<AES-256-GCM-ciphertext>",
  "tag":"<16-byte-GCM-tag>"
}
```

`reload` 刷新配置来源中的密钥；`rewrap` 使用当前主密钥重包已有资源；`rotate` 生成新主密钥、重包并按后端规则退役旧密钥。只有支持托管密钥的配置才能执行一键轮转。报告字段：

```json
{
  "public_key":"<new-PEM-public-key>",
  "rewrapped":1,
  "skipped":0,
  "failed":0,
  "retired_keys":1,
  "purged_keys":0
}
```

`rewrap` 报告为 `total/rewrapped/skipped/failed`。不能只检查 HTTP 200：还必须检查 `failed`，失败资源可能使旧密钥无法安全退役。

`EncryptedDb(MySQL)` 在数据库中协调多副本轮转，其他副本在 key-ring bump 轮询后刷新缓存；客户端轮转后也应重新获取 `pubkey`。`EncryptedLocalFs` 仍是单副本方案，不要用共享 PVC 冒充数据库一致性。`EncryptedDb(SQLite)` 同样不是 HA 方案。

## 2. AS API：两组等价别名

| 操作 | `/api/attestation-service` | `/api/as` |
| --- | --- | --- |
| 提交证明 | `POST /api/attestation-service/attestation` | `POST /api/as/attestation` |
| 获取挑战 | `POST /api/attestation-service/challenge` | `POST /api/as/challenge` |
| 获取签名证书 | `GET /api/attestation-service/certificate` | `GET /api/as/certificate` |
| 获取 JWKS | `GET /api/attestation-service/jwks` | `GET /api/as/jwks` |
| OIDC discovery | `GET /api/attestation-service/.well-known/openid-configuration` | `GET /api/as/.well-known/openid-configuration` |
| 设置策略 | `POST /api/attestation-service/policy` | `POST /api/as/policy` |
| 获取策略 | `GET /api/attestation-service/policy/{id}` | `GET /api/as/policy/{id}` |
| 列出策略 | `GET /api/attestation-service/policies` | `GET /api/as/policies` |
| 删除策略 | `DELETE /api/attestation-service/policy/{id}` | `DELETE /api/as/policy/{id}` |

### 2.1 直接证明

请求格式为 `verification_requests` 数组，**不是**旧文档中顶层的 `tee/evidence/runtime_data`：

```json
{
  "verification_requests": [{
    "tee":"sample",
    "evidence":"<base64url-no-padding-evidence-json>",
    "runtime_data":{"structured":{"challenge_token":"<extra-params.jwt>"}},
    "runtime_data_hash_algorithm":"sha384"
  }],
  "policy_ids":["default"]
}
```

`evidence` 的格式由 verifier 定义；样例只是请求结构。运行时数据也支持 `{"raw":"<base64url>"}`。可选初始化数据使用 `{"init_data_digest":"<base64url>"}` 或 `{"init_data_toml":"<raw-TOML-text>"}`。当前必须显式提供 `policy_ids`。

成功响应是**原始 JWT 字符串**，不是 KBS 的 `{"token":...}` 对象。签名算法和 claims 由 token broker 决定（例如 Simple 为 RS384、OIDC 为 RS256）。

### 2.2 挑战、证书与 OIDC

通用挑战请求是 `{}`，响应包含 `nonce` 和 `extra-params.jwt`。客户端把后者放入结构化运行时数据的 `challenge_token` 中，并将该运行时数据绑定到证据 report-data。传入 `tee` 时改为该 verifier 的补充挑战流程，响应不保证是上述 JSON；例如 `{"tee":"sample"}` 当前返回空响应体。

挑战 JWT 校验签名和过期时间，不保证五分钟有效期内的一次性消费。challenge-key 通过文件/Secret 配置，每次请求重新加载；轮转后旧 key 签出的挑战失效。**资源 `rotate` 不会轮转 AS 签名密钥或 challenge-key。**

- `certificate`：配置证书时返回 PEM 和 `application/x-pem-file`；未配置时返回 404。此端点实时读取证书文件。
- `jwks`：当前只有配置显式 signer 的 OIDC broker 发布 JWKS；Simple/EAR 或未配置 signer 时返回 404，不表示服务宕机。
- discovery：配置 OIDC broker 的 `oid_config` 时返回 `issuer/jwks_uri/id_token_signing_alg_values_supported`；否则返回 404。
- 签发证明 token 使用的签名密钥和证书链在服务构造时加载。更新 token signer 应协调重启 AS 及验证端信任配置；不要把证书端点的热读取误认为 token 签名密钥也热轮转。

### 2.3 AS 策略管理

POST 的结构与 KBS 证明策略相同。GET 单策略返回 Base64URL 策略字符串，列表返回：

```json
[{"policy-id":"default","policy-hash":"<digest>"}]
```

注意 AS 列表是数组，而 KBS 的 `attestation-policies` 是 ID 到摘要的对象。Gateway `/policies` 转发到 RESTful AS 的 `/policy`，不是 `/policies`。

## 3. RVPS API

这组请求经 Gateway -> KBS -> AS -> RVPS 转发，全部需要 **KBS 管理员 JWT**；不是由 Gateway 直接执行参考值写入。Gateway 配置中的 RVPS gRPC 连接用于服务健康检查。

| 操作 | 接口 | 请求 / 成功响应 |
| --- | --- | --- |
| 查询 | `GET /api/rvps/query` | 返回名称到策略可见值的 JSON 对象 |
| 注册 | `POST /api/rvps/register` | `{"message":"<serialized-RVPS-message>"}` |
| 批量设置 | `POST /api/rvps/set_reference_value_list` | `{"rv_list":[...]}` |
| 删除 | `DELETE /api/rvps/delete/{name}` | 删除该参考值 |

注册 message 是嵌套的 JSON **字符串**，其中 payload 使用 STANDARD Base64，例如：

```json
{"version":"0.1.0","type":"sample","payload":"<standard-base64-json-object>"}
```

sample payload 可为 `{"sample.svn":["1"],"my.config":{"enabled":true}}`。字符串数组兼容旧摘要格式，重复注册时合并摘要；任意 JSON 值作为原子策略可见值保存，重复注册时替换该值。过期参考值不应再出现在有效查询结果中。

批量设置的推荐格式：

```json
{
  "rv_list": [{
    "id":"cvm_container_proxy",
    "version":"artifact-version",
    "type":"container",
    "rv_name":"optional.custom.name",
    "provenance_info":{
      "type":"rv-release-manifest",
      "rekor_url":"https://log2025-1.rekor.sigstore.dev",
      "rekor_api_version":2
    },
    "provenance_source":{
      "protocol":"oci",
      "uri":"oci://registry.example/trustee/provenance:v1",
      "artifact":"bundle"
    },
    "operation_type":"refresh"
  }]
}
```

未指定 `rv_name` 时，新格式使用 measurement `id`；名称不能为空白。`refresh` 替换旧值，`add` 追加值。历史 `slsa-intoto-statements` 路径保留兼容，旧格式默认名称为 `measurement.$type.$artifact-id`。启用 `fs` 的受信测试环境也支持 `protocol=file` 的本地 fixture；这不是远程 OCI 拉取或 Rekor 服务可用性的验证。

## 4. Gateway 自身 API

| 操作 | 接口 | 请求 / 响应 |
| --- | --- | --- |
| 证明审计 | `GET /api/audit/attestation` | 返回 `{"data":[...],"total":N}` |
| 资源审计 | `GET /api/audit/resources` | 返回 `{"data":[...],"total":N}` |
| 基本健康 | `GET /api/health` | `{"status":"ok"}` |
| 服务健康 | `GET /api/services-health` | gateway/kbs/as/rvps 各自的 status/message/timestamp |
| AA 心跳 | `POST /api/aa-instance/heartbeat` | `AAInstanceInfo` 请求头是实例信息 JSON |
| 活跃 AA 列表 | `GET /api/aa-instance/list` | `active_aa_instances/count/timestamp` |
| Credential 文件 | `GET /api/credential` | 配置文件的原始字节，`application/octet-stream` |

审计记录是异步写入，查询端应允许短暂延迟。证明审计覆盖 KBS 和两组 AS 别名，`source_service` 为 `kbs` 或 `attestation-service`；不保存原始 evidence 请求体。资源审计包含 GET、POST、DELETE。

共同过滤参数：`session_id/instance_id/successful/start_time/end_time/limit/offset`。时间使用 RFC3339；证明审计还支持 `source_service`，资源审计还支持 `repository/type/tag/method`。`total` 是过滤后的总数，不是当前页大小。

`AAInstanceInfo` 最小示例为 `{"instance_id":"my-instance"}`，也支持 `eas_instance_id` 兼容映射、image_id/instance_name/ip 等字段。重复心跳更新原实例，不应创建重复行。活跃窗口由 `heartbeat_timeout_minutes` 决定。

未配置 Credential 或文件不存在时返回 404；读取异常返回 500。服务健康接口即使某个后端异常也可能返回 HTTP 200，调用方必须逐项检查 `status`，不能只看 HTTP 状态码。

## 5. 缓存和错误边界

当前 Gateway **没有独立的通用 cache list/clear API**。`resource/reload` 是托管密钥缓存刷新，不是 TDX collateral 或策略编译缓存的清空接口。

共享模式下，资源策略读取权威存储；AS 策略编译缓存按内容摘要刷新，RVPS 查询缓存的作用域是单次证明。E2E 会在不重启的情况下更新策略及参考值，再重新证明，验证不会沿用旧决策；也验证 EncryptedDb 轮转后的另一副本公钥与资源读取。

当前错误行为包含历史兼容边界：

- KBS 管理认证失败、缺少或伪造证明 JWT：401；资源策略拒绝：403。
- KBS RCAR 无效会话、nonce 不匹配等握手失败：目前为 502，而不是统一的 400/401。
- RESTful AS 的 JSON 格式/TEE 参数错误：400；无效或过期 challenge token：401，并提供 `application/problem+json` 的 `code/detail/retryable` 等字段。
- 当前部分 AS 策略拒绝、KBS 存储资源不存在、不支持的托管密钥操作仍返回 500。不要将这些状态误写为已经实现的 404/403；后续错误码改造需同步更新测试和文档。
- Gateway 访问上游失败时返回错误，不能把仅有健康 HTTP 200 当作完整服务链路成功。

## 6. E2E 覆盖与运行

[测试说明](test/e2e/README.md) 包含本地运行和 CI 细节。`Gateway API E2E` 工作流使用真实 Gateway/KBS/gRPC AS/RESTful AS/RVPS 进程，并测试：

1. 45 个 API 操作、两组 AS 别名，以及成功/拒绝/不支持响应。
2. LocalFs、EncryptedLocalFs、EncryptedDb/SQLite、SharedStore/MySQL、EncryptedDb/MySQL；后两种启动双副本。
3. nonce/公钥绑定、独立 JWT 验签、JWE 解密、资源 CRUD、策略 CRUD、参考值注册/追加/覆盖/删除、证书/OIDC、密钥维护、心跳和审计。
4. KBS/AS/Gateway 重启后的持久化、跨副本会话和数据可见性，以及策略/RVPS/密钥缓存刷新。
5. 默认解释器和 `regorus-regovm` 两种策略引擎。新增路由或未维护文档/E2E 清单会被覆盖门禁发现。

**验证边界：**通用 CI 使用 `sample` verifier，不验证 TDX/SNP/CSV/TPM 等真实硬件签名、采证和生产证书链；也不声称验证云 KMS、PKCS#11、外部 OCI/Rekor 的真实服务。sample 不能证明运行环境可信，不能用于生产信任判断。WASM 保持原有内存存储设计，由既有 WASM 检查验证，不属于此原生进程 E2E。
