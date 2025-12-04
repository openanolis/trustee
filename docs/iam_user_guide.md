# Trustee IAM 服务用户指南

## 1. 概述

Trustee IAM（Identity & Access Management）提供统一的账号、主体、资源、角色与策略管理能力，用于在多租户、多方协作场景下建立可信的授权闭环。该服务是 Trustee 体系中所有信任关系的中心，负责：

- 管理账户（Account）与主体（Principal）的身份。
- 注册所有需要保护的资源（Resource），并生成 ARN。
- 定义角色（Role），并附带信任/访问策略（Policy）。
- 通过 STS 样式的 `AssumeRole` 接口颁发短期会话令牌。
- 提供 `authz/evaluate` 接口供 KBS、Gateway、guest-components 等组件执行实时授权判断。

## 2. 架构与部署

IAM 服务以 Actix Web 提供 REST API，默认监听 `0.0.0.0:8090`。核心模块如下：

| 模块 | 说明 |
| --- | --- |
| `config.rs` | 解析 `iam.toml` 配置，包括服务监听、签名参数等。 |
| `models.rs` | 定义账户、主体、资源、角色、策略及请求/响应结构。 |
| `policy.rs` | 实现 Action/Resource/Condition 的匹配逻辑。 |
| `attestation.rs` | 解析来自 TEE 环境的 Base64 JSON 证明。 |
| `token.rs` | HMAC-SHA256 的 JWT 签发与校验。 |
| `service.rs` | 处理具体业务流程（创建实体、AssumeRole、鉴权）。 |
| `api.rs` | 将 HTTP 请求映射到服务方法。 |

### 2.1 配置示例 (`iam/config/iam.toml`)

```toml
[server]
bind_address = "0.0.0.0:8090"

[crypto]
issuer = "trustee-iam"
hmac_secret = "replace-with-strong-secret"
default_ttl_seconds = 900
```

- `issuer`：Token 中的 `iss` 字段。
- `hmac_secret`：HMAC-SHA256 的共享密钥，建议在生产环境替换为 KMS/HSM 托管密钥。
- `default_ttl_seconds`：未显式指定 `requested_duration_seconds` 时的默认有效期。

## 3. API 快速入门

### 3.1 创建账号

```bash
curl -X POST http://localhost:8090/accounts \
     -H 'Content-Type: application/json' \
     -d '{
           "name": "demo-account",
           "labels": { "tenant": "alpha" }
         }'
```

响应：

```json
{
  "account": {
    "id": "acct-5f5c7a2b-...",
    "name": "demo-account",
    "labels": { "tenant": "alpha" },
    "created_at": "2025-12-04T06:00:00Z"
  }
}
```

### 3.2 创建主体

```bash
curl -X POST http://localhost:8090/accounts/acct-xxx/principals \
     -H 'Content-Type: application/json' \
     -d '{
           "name": "runtime-a",
           "principal_type": "Runtime",
           "attributes": { "values": { "cluster": "prod" } }
         }'
```

### 3.3 注册资源

```bash
curl -X POST http://localhost:8090/resources \
     -H 'Content-Type: application/json' \
     -d '{
           "owner_account_id": "acct-xxx",
           "resource_type": "kbs/key",
           "tags": { "tier": "gold" }
         }'
```

服务会返回生成的 ARN，如 `arn:trustee::acct-xxx:kbs/key/res-123`.

### 3.4 创建角色

```bash
curl -X POST http://localhost:8090/roles \
     -H 'Content-Type: application/json' \
     -d '{
           "name": "trusted-runtime",
           "trust_policy": {
             "statements": [{
               "effect": "Allow",
               "actions": ["sts:AssumeRole"],
               "resources": ["role/*"],
               "conditions": [{
                 "operator": "StringEquals",
                 "key": "principal.accountId",
                 "values": ["acct-xxx"]
               }]
             }]
           },
           "access_policy": {
             "statements": [{
               "effect": "Allow",
               "actions": ["kbs:GetKey"],
               "resources": ["arn:trustee::acct-xxx:kbs/key/*"]
             }]
           }
         }'
```

### 3.5 AssumeRole

```bash
curl -X POST http://localhost:8090/sts/assume-role \
     -H 'Content-Type: application/json' \
     -d '{
           "principal_id": "prn-xxx",
           "role_id": "role-yyy",
           "session_name": "demo-session",
           "attestation_token": "<base64-json-claims>"
         }'
```

返回字段：

| 字段 | 说明 |
| --- | --- |
| `token` | HMAC-SHA256 签名的 JWT，供 Gateway/KBS/guest-components 使用。 |
| `expires_at` | RFC3339 时间戳。 |

### 3.6 鉴权评估

```bash
curl -X POST http://localhost:8090/authz/evaluate \
     -H 'Content-Type: application/json' \
     -d '{
           "token": "eyJhbGciOiJIUzI1NiIs...",
           "action": "kbs:GetKey",
           "resource": "arn:trustee::acct-xxx:kbs/key/res-123",
           "context": { "caller_ip": "10.0.0.8" }
         }'
```

返回：

```json
{ "allowed": true }
```

## 4. 与其他组件的协作

1. **Gateway**：新增 `/api/iam` 前缀，自动将请求转发至 IAM；因此外部访问入口保持统一。
2. **KBS**：可在获取密钥之前调用 `/authz/evaluate`，并将资源 ARN/Action 作为输入；若 `allowed=false` 则拒绝请求。
3. **guest-components / TNG**：
   - guest-components 在加载模型时先通过 attestation 获取临时令牌，再在访存/推理前验证 token 的 `env`、`principal` 等字段。
   - TNG 可将用户凭证转换为 IAM 的 `AssumeRole` 请求，从而生成统一的推理会话 token。

典型流程如下：

```
Principal -> Gateway (/api/iam/sts/assume-role)
          -> IAM (验证信任策略 + Attestation)
          -> 返回短期 token
Principal + Token -> 服务 (KBS/TNG) -> /api/iam/authz/evaluate
                                   -> 允许访问受保护资源
```

## 5. 最佳实践

1. **最小权限**：为不同协作者创建独立角色，细化 `actions` 与 `resources`，避免使用通配符 `*`。
2. **Attestation 绑定**：在信任策略与访问策略中引入 `env.tee_type`、`env.measurement` 条件，确保 token 只能在可信环境中获取与使用。
3. **短期令牌**：默认 TTL 为 15 分钟，可按场景缩短；建议业务侧缓存但不要长期保存。
4. **审计**：通过 Gateway 或服务侧日志记录 `action`、`resource`、`principal`、`allowed` 等字段，便于排查授信问题。

## 6. 故障排查

| 现象 | 排查步骤 |
| --- | --- |
| `401 Unauthorized` | 检查 `AssumeRole` 请求中的 `principal_id` / `role_id` 是否存在，信任策略是否允许该主体。 |
| `403` (evaluate 返回 `{ "allowed": false }`) | 查看角色的 `access_policy` 是否覆盖对应 Action/ARN；确认传入的 `context` 字段（IP、标签等）是否满足条件。 |
| `400 invalid attestation token` | 确认 `attestation_token` 为 Base64 编码且内容为 JSON 对象。 |
| Token 过期 | 调用 `AssumeRole` 时指定较短的 `requested_duration_seconds`；定时刷新。 |

如需要更高级的策略操作（数值、时间区间等），可扩展 `policy.rs` 中的 `ConditionOperator`，并同步更新 Gateway/调用方的请求格式。

---

通过以上步骤即可完成 IAM 服务的部署与调用。如果需要进一步的集成协助，可参考 `trustee-iam-architecture.md` 与 `trustee_gateway_api.md` 中的整体流程说明。

