# Trustee IAM 服务架构设计（中文）

## 1. 背景与目标

Trustee IAM（Identity & Access Management）旨在为多参与方（基础设施提供方、模型提供方、推理调用方等）提供统一的身份、资源和策略管理能力。其核心目标包括：

1. **统一身份管理**：抽象出 Account / Principal / ServicePrincipal 等通用概念，避免与具体业务角色（WP/MP/IU）强耦合。
2. **资源与 ARN 命名**：通过统一的资源注册表，为 KBS、模型、数据等提供可追踪的 ARN。
3. **角色-策略体系**：以 Trust Policy + Access Policy 的组合实现跨租户授权、联合授权、条件约束等场景。
4. **可验证的临时凭证**：通过 STS `AssumeRole` 颁发短期 Token，将安全上下文（账户、主体、TEE 证明等）绑定在一起。
5. **通用接入点**：Gateway、KBS、TNG、guest-components 等均可通过标准 REST API 调用 IAM，实现鉴权放大器的角色。


## 2. 核心概念

| 概念 | 说明 |
| --- | --- |
| Account | 租户/组织边界，包含若干 Principal 与 Resource。 |
| Principal | 具体身份：人、服务、运行时、外部实体等。 |
| Resource | 需要受控访问的目标，注册时生成 ARN（如 `arn:trustee::acct-1:kbs/key/res-1`）。 |
| Role | 权限集合，由信任策略（谁能扮演）与访问策略（能访问什么）组成。 |
| Policy | PolicyDocument，包含 Statement（Effect + Actions + Resources + Conditions）。 |
| STS Token | `AssumeRole` 成功后签发的短期 JWT，携带 principal/role/env/自定义上下文。 |
| Evaluate API | 给定 token + action + resource，在策略引擎做 Allow/Deny 判断。 |


## 3. 系统组件

```
┌──────────┐      ┌───────────┐      ┌────────────┐
│ 调用方    │ ---> │ Gateway    │ ---> │ IAM API     │
│ (终端、   │      │ (/api/iam) │      │             │
│  KBS/TNG) │      └────┬──────┘      │ ┌─────────┐ │
└──────────┘           │             │ │Policy    │ │
                       │             │ │Engine    │ │
                       │             │ └─────────┘ │
                       │             │ ┌─────────┐ │
                       └────────────> │ Token    │ │
                                     │ Signer   │ │
                                     │ └─────────┘ │
                                     │ ┌─────────┐ │
                                     │ │ Storage │ │
                                     │ └─────────┘ │
                                     └────────────┘
```

- **API 层（Actix Web）**：处理 `POST /accounts`、`/roles`、`/sts/assume-role`、`/authz/evaluate` 等 REST 请求。
- **Service 层**：封装业务逻辑，负责参数校验、资源 ID 生成、上下文构建。
- **Storage**：当前为内存实现（HashMap + RwLock），后续可替换为持久化存储。
- **Policy Engine**：判断 Action/Resource 是否匹配，并根据 Condition 解析上下文（principal/env/request 等）。
- **Attestation 模块**：解析 Base64 JSON 形式的 TEE Claims，可在信任策略或访问策略中引用。
- **Token Signer**：使用 HMAC-SHA256 (JWT) 颁发/验证 Token，后续可接入 KMS/HSM。


## 4. 数据流与关键流程

### 4.1 资源注册
1. 资源所有者调用 `POST /resources`，指定 `owner_account_id` 与 `resource_type`。
2. 服务生成 `res-xxx` 并构造 ARN（`arn:trustee::<account>:type/res-id`）。
3. 返回资源对象，供策略引用。

### 4.2 角色创建
1. 维护者调用 `POST /roles`，提供 `trust_policy` 与 `access_policy`。
2. IAM 存储 Role 元数据，并在后续 `AssumeRole`/`Evaluate` 时引用。

### 4.3 AssumeRole
1. Principal 携带（可选）Attestation Token 调用 `/sts/assume-role`。
2. IAM 验证 Attestation，构造上下文：`principal`、`env`、`request`。
3. Policy Engine 运行角色的 Trust Policy；若允许，则调用 TokenSigner 颁发 Token。

### 4.4 Access Evaluate
1. 业务服务（KBS/TNG 等）调用 `/authz/evaluate`，传入 Token + Action + Resource。
2. IAM 验证 Token，加载角色 Access Policy。
3. Policy Engine 匹配 action/resource + condition，返回 Allow/Deny 布尔值。


## 5. 策略上下文设计

PolicyEngine 接收 `MatchContext = { principal, env, resource, request }`，字段说明：

| 字段 | 示例 | 来源 |
| --- | --- | --- |
| `principal` | `{ id, accountId, type, attributes }` | Principal 信息 |
| `env` | `{ tee_type, measurement }` | Attestation Claims |
| `resource` | `{ arn, ownerAccountId, resourceType, tags }` | `Evaluate` 时根据 ARN 查得 |
| `request` | `{ action, resource, context }` | API 调用参数 |

Condition Key 使用点号访问，如 `principal.accountId`、`env.tee_type`、`request.context.ip` 等。


## 6. API 汇总

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST /accounts` | 创建账号 |
| `POST /accounts/{account_id}/principals` | 创建主体 |
| `POST /resources` | 注册资源（生成 ARN） |
| `POST /roles` | 创建角色（含策略） |
| `POST /sts/assume-role` | 获取 STS Token，支持 attestation |
| `POST /authz/evaluate` | 校验 Token + Action + Resource |

**说明**：Gateway 中的 `/api/iam/**` 与上表完全映射，便于外部组件统一调用。


## 7. 部署与运维

1. **容器化**：`Dockerfile.iam` 构建二进制；`docker-compose.yml` 中已有 `iam` 服务，并被 Gateway 依赖。
2. **配置**：默认 `iam/config/iam.toml`，可通过挂载覆盖。生产环境需替换 `hmac_secret`。
3. **dist 集成**：在 `dist/start.sh` 中加入 IAM 启动逻辑；systemd 单元 `iam.service` 支持单机部署。
4. **日志 & 监控**：当前使用 stdout + logrotate；建议通过 `RUST_LOG` 设置调试级别，并接入外部日志系统。


## 8. 与其他组件的关系

- **Gateway**：代理 `/api/iam/*` 请求；更新配置后可通过 `iam.url` 指向不同环境。
- **KBS**：在发放密钥前可调用 `/authz/evaluate`，确保请求方拥有相应角色。
- **Attestation Service**：IAM 不直接依赖 AS，但通过 Attestation Token 获取 TEE 信息，与 `env.*` 条件结合。
- **Guest Components / TNG**：可在可信环境内使用 Attestation Token 兑换 STS Token，实现端到端闭环。


## 9. 后续演进方向

1. **持久化存储**：替换内存 Store，增加多副本或外部数据库，更好地支持生产部署。
2. **策略引擎增强**：支持数值比较、时间窗口、集合运算等更丰富的条件表达式。
3. **Token 托管**：接入 KMS/HSM 管控密钥，或支持多种签名算法（如 ES256、EdDSA）。
4. **多租户隔离**：在 API 层引入多租户/AuthN 机制（OAuth2/OIDC），细化调用方权限。
5. **审计日志**：记录 `AssumeRole` / `Evaluate` 事件，方便安全分析与计费。
6. **SDK & 模板**：提供语言 SDK、策略模板，降低接入成本。


## 10. 总结

Trustee IAM 通过 **Account + Resource + Role + Policy + STS** 的组合，提供通用且可扩展的授权体系。在现有实现中，核心流程已具备“注册资源 → 创建角色 → AssumeRole → Evaluate”闭环，并可与 Gateway/KBS/guest-components 等其他组件协同使用。随着持久化、审计与 SDK 的完善，IAM 将成为 Trustee 生态中连接多方信任的关键枢纽。

