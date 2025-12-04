# Trustee IAM 与 KBS / Attestation Token / TNG / guest-components 联动设计说明

本说明文档聚焦于：**在已有的 KBS、Attestation、TNG、guest-components 体系基础上，IAM 如何嵌入并形成端到端的可信授权闭环**。  
对应的整体架构思想可以结合根目录下的 `trustee-iam-architecture.md` 一起阅读。

---

## 1. 参与组件与定位

- **IAM 服务（本仓库 `iam`）**
  - 提供统一的账号（Account）、主体（Principal）、资源（Resource）、角色（Role）、策略（Policy）与 Token 能力。
  - API 示例：
    - `POST /accounts` / `POST /principals` / `POST /resources` / `POST /roles`
    - `POST /sts/assume-role`
    - `POST /authz/evaluate`

- **KBS（Key Broker Service）**
  - 管理密钥、机密资源（例如模型加密密钥、启动密钥等）。
  - 接收来自可信运行环境的证明（Attestation）和请求，按策略将密钥下发给客户端（如 guest-components）。

- **Attestation Service（AS）**
  - 面向 TEE 运行时提供远程证明接口。
  - 验证测量值、证书链等，生成 Attestation Token 或 Attestation Result（包含安全声明 Claims）。

- **TNG（如推理网关 / Token Generation Service）**
  - 面向推理调用方和上层应用，将用户身份、调用意图转换为一组 Token（可能包括 IAM STS Token）。
  - 是“用户世界”与“受保护运行时世界”的连接器。

- **guest-components（机密 VM / 容器内部的 Agent/Runtime）**
  - 在 TEE 内运行，负责：
    - 携带 Attestation 结果向 IAM / KBS 等组件证明自己；
    - 拉取模型或密钥；
    - 执行推理请求。

- **Gateway**
  - 作为统一入口，将 `/api/iam`、`/api/kbs`、`/api/attestation-service` 等请求代理到后端服务。
  - 当前实现中，`/api/iam/**` 全量转发到 IAM。

---

## 2. 核心设计思想：将“身份 + 环境 + 资源”统一成策略可见上下文

IAM 的目标不是替代 KBS 或 AS，而是将它们已有的“证明结果”和“资源概念”统一在一个策略评估框架下：

1. **身份（Principal）**：谁在发起请求？
2. **环境（Env / Attestation Claims）**：这个请求从什么运行环境发出？TEE 测量值、平台类型是否可信？
3. **资源（Resource）**：操作的目标是哪个 KBS Key / 模型 / Endpoint / 部署实例等？
4. **操作（Action）**：例如 `kbs:GetKey`、`model:Invoke`、`endpoint:Invoke`。

IAM 通过：

- Attestation 模块：将 Attestation Token 转换为 `env.*`；
- Resource Registry：将 KBS 的 Resource ID 统一成 ARN；
- STS Token：将 Principal + Role + Env + Custom Context 封装成一个短期 Token；
- Policy Engine：在 Evaluate 阶段同时看到 action/resource/principal/env 等信息，

从而帮助 KBS、TNG、guest-components 简化授权逻辑，仅需在关键点调用 IAM 即可。

---

## 3. Attestation Token 与 IAM 的联动

### 3.1 引导关系

Attestation Token 在当前设计中被定位为 **AssumeRole 的输入材料**，流程如下：

1. guest-components 或运行时在启动时向 AS 发起证明请求。
2. AS 返回 Attestation 结果（可包含 TEE 测量值、证书链、平台信息等）。
3. guest-components 将该结果封装/转换为 Base64 JSON 字符串（Attestation Token）。
4. guest-components 调用 IAM 的 `POST /sts/assume-role`，将 Attestation Token 作为 `attestation_token` 字段上传。
5. IAM 内部：
   - 使用 `attestation.rs` 解析 token 为 `Map<String, Value>`（`env` 部分）；
   - 将 `env` 与 `principal`、`request` 一起作为策略上下文；
   - 使用角色 trust_policy 中的 Condition 判断是否允许该环境和主体 `AssumeRole`。
6. 若通过，IAM 签发 STS Token，后续由 guest-components/KBS/TNG 等组件使用。

### 3.2 策略中的 Attestation Claim

在 Trust Policy 或 Access Policy 中，可以写出类似规则：

- `env.tee_type == "TDX"`
- `env.measurement in { "0x1234...", "0xabcd..." }`
- `env.owner == "cloud-provider-A"`

Policy Engine 将 `env` 视为普通 JSON 对象，对这些字段做字符串匹配或通配匹配。  
接口层无需关心 Attestation 的内部格式，只需要约定好 Claim 字段名称与含义即可。

---

## 4. IAM 与 KBS 的联动

### 4.1 KBS 资源与 ARN 映射

在已有 KBS 中，“Key / Secret / Blob 等资源”已存在自己的标识（如 repository/path、key-id 等）。IAM 将其抽象为：

- `arn:trustee::acct-123:kbs/key/key-001`
- `arn:trustee::acct-123:kbs/blob/blob-xyz`

映射关系可以在：

- 部署时由控制面统一注册；或
- 在 KBS 首次访问对应资源时动态注册（lazy registration）。

### 4.2 KBS 调用 IAM 进行授权评估

KBS 在“即将返回 Key 或 Secret”前，引入如下授权钩子：

1. 从来访请求中解析出：
   - 主体 STS Token（由 guest-components 或上层服务提供）；
   - 目标资源 ARN；
   - 访问操作 Action（如 `kbs:GetKey`、`kbs:Decrypt`）。
2. 调用 IAM 的 `POST /authz/evaluate`：
   ```json
   {
     "token": "<sts-token>",
     "action": "kbs:GetKey",
     "resource": "arn:trustee::acct-123:kbs/key/key-001",
     "context": {
       "caller_ip": "10.0.0.5",
       "channel": "kbs"
     }
   }
   ```
3. IAM：
   - 验证 token（签名、时效）；
   - 解析其中的 `sub`、`tenant`、`role`、`env`、`custom`；
   - 根据 resource ARN 装配 `resource` 上下文；
   - 执行角色 Access Policy：
     - 若匹配，则返回 `{ "allowed": true }`；
     - 否则返回 `{ "allowed": false }`。
4. KBS 根据结果决定是否下发 Key/Secret。

从而实现：

- 授权逻辑从 KBS 抽象出来，由 IAM 统一管理；
- 策略统一控制“哪个运行环境 + 哪个主体 + 对哪类 Key 拥有哪些操作能力”。

---

## 5. IAM 与 TNG 的联动

IAM 与 TNG 的联动应当站在“网络平面 + 证明平面”和“授权平面”分层的角度来设计。

### 5.1 TNG 在整体方案中的角色

- 在 **数据平面** 上：
  - TNG 通过 `add_ingress` / `add_egress` 配置（`mapping` / `http_proxy` / `socks5` / `netfilter` 等模式），将业务流量封装进经 RA 保护的隧道中。
  - 在 `attest` / `verify` 字段开启时，TNG 会对接 AS，发起或验证远程证明，只有通过验证的对端才能建立隧道。
- 在 **控制/信任平面** 上：
  - TNG 自身只负责 **“保证对端运行环境可信 + 建立加密通道”**；
  - 业务层的“用户是谁/能干什么”不由 TNG 直接决策，而是交由上层（例如 Gateway 或具体服务）与 IAM 协作完成。

换句话说：**TNG 给 IAM/KBS/Gateway 提供“连接来自可信 TEE 的网络上下文”，而 IAM 在此基础上做“谁对什么资源拥有什么权限”的细粒度授权。**

### 5.2 推荐的协作模式

1. **TNG + AS：负责建立可信通路**
   - 在 client/container 侧部署 TNG（`attest` 角色），在服务端（靠近 Gateway/KBS/IAM 一侧）部署 TNG（`verify` 角色）。
   - server 侧 TNG 通过配置的 `as_addr` 与 `policy_ids` 调用 AS，验证对端环境（例如 TDX VM / 可信容器），并按策略决定是否接受连接。
   - 一旦连接建立，TNG 将业务 TCP/HTTP 流量透明地转发到本地的 Gateway/KBS/IAM 服务端口。

2. **Gateway/KBS/IAM：在应用层感知“连接已被 TNG 保护”**
   - 对应用服务（Gateway/KBS/IAM）而言，请求源现在包括两层含义：
     - 网络上：来自本地 TNG verify 实例（通常是 127.0.0.1 或同一 VPC 内地址）；
     - 语义上：实际来源是通过 RA 验证的远端 TEE 环境。
   - 目前 TNG 默认并不会修改上层 HTTP 头，但可在后续演进中考虑以下扩展：
     - server 侧 TNG 在完成验证后，将 Attestation Result 的摘要（如 status、platform、measurement hash）注入到上游 HTTP 头中（例如自定义 `X-TNG-Attestation`）；
     - Gateway/KBS 将这一摘要转换为 IAM `AssumeRole` / `authz/evaluate` 所需的 `attestation_token` 或 `env.*` 字段。

3. **IAM：只承担“证明 +身份 + 资源”的策略裁决，不关心 TNG 的内部细节**
   - 对 IAM 而言，TNG 是否存在、采用何种隧道协议，是透明的；
   - IAM 只需要：
     - 从上游（Gateway/KBS/guest-components）获取 Attestation Token 或环境 Claims；
     - 在 Condition 中使用 `env.tee_type`、`env.measurement` 等字段；
     - 针对 `action=...` / `resource=arn:...` 做 Allow/Deny 判定。

### 5.3 典型链路（网络 + 授权）

以“client 容器访问 KBS 获取密钥”为例：

1. client 容器将请求发往本地 TNG ingress（例如 http_proxy 模式）。
2. 本地 TNG 使用 OHTTP + RA 与服务端 TNG 建立隧道，服务端 TNG 通过 AS 验证 client 侧 TEE 证据。
3. 通路建立后，服务端 TNG 把 HTTP 请求转发到本机的 Gateway/KBS。
4. KBS 在处理 `/kbs/v0/...` 时，从请求中取出：
   - 来自上层的 IAM STS Token（身份 + 角色）；
   - 可选的 Attestation Result Token（如果通过 TNG / AS 传递上来）。
5. KBS 调用 IAM 的 `/authz/evaluate`，在 Context 中写入 `env.*`（来自 Attestation）和 `request.*` 等字段。
6. IAM 返回 `{ allowed: true|false }`，KBS 决定是否返回密钥。

在整个过程中：

- **TNG 只负责“确保链路对端的运行环境可信，并安全转发流量”**；
- **IAM 只负责“在这个前提下，对具体操作做授权判断”**；
- 二者通过 Gateway/KBS 等上层服务桥接起来，而非直接互相调用。

---

## 6. IAM 与 guest-components 的联动

guest-components 位于 TEE 内部，是 Attestation 的主要执行者，也是实际执行“获取密钥 / 加载模型 / 执行推理”的组件。

### 6.1 运行时自举（Runtime Bootstrap）

1. guest-components 在 TEE 启动后，向 AS 发起远程证明，获得 Attestation 结果。
2. guest-components 将 Attestation 结果编码为 Base64 JSON，调用 IAM 的 `AssumeRole`：
   - 该 role 一般为“受保护运行时角色”，其 Trust Policy 要求：
     - `env.tee_type` 合法；
     - `env.measurement` 在白名单内；
     - `principal` 满足某些 account id/标签约束。
3. IAM 返回运行时 STS Token，guest-components 将其缓存，用于后续访问 KBS 或其他服务。

### 6.2 运行时访问检查

当 guest-components 要从 KBS 拉取密钥时：

1. 使用上一步获取的 STS Token 调用 KBS 的 `/kbs/v0/...` API；
2. KBS 内部调用 IAM 的 `/authz/evaluate` 判定；
3. 若通过，KBS 发送密钥，guest-components 在 TEE 内解密/使用。

同理，在后续访问 TNG 或其他服务时，也可以采用同一 STS Token 作为“运行时身份”，避免重复 Attestation。

---

## 7. 典型端到端场景串联（以“通过 TNG 访问 KBS”为例）

以“应用容器通过 TNG 隧道访问 KBS 获取密钥”为例，整体链路如下：

1. **应用容器 → 本地 TNG（ingress）**
   - 应用将所有访问 KBS 的流量（例如 `http://kbs.internal:8080`）配置为通过 TNG 的 `http_proxy` 或 `socks5` 入口。
   - TNG ingress 将明文流量封装，并扮演 Attester，准备与 server 侧 TNG 建立 OHTTP/RA 隧道。

2. **TNG ingress ↔ TNG egress + AS**
   - TNG egress 侧（靠近 KBS/Gateway 的一侧）在 `verify` 配置下向 AS 发起远程证明验证；
   - AS 对 TEE 证据进行评估，返回 Attestation Result（或标记为不可信）；
   - TNG egress 仅在验证通过时允许隧道建立。

3. **TNG egress → Gateway/KBS**
   - 隧道建立后，KBS/Gateway 实际看到的网络连接来自 TNG egress（例如 `127.0.0.1:port`），但语义上代表“某个通过 RA 验证的远端 TEE 环境”；
   - 如果后续扩展 TNG，将 Attestation Result 摘要通过 HTTP 头传给 Gateway，则 Gateway 可以据此构造 `attestation_token` 提供给 IAM。

4. **KBS → IAM（authz/evaluate）**
   - 应用在访问 KBS 前，已通过业务层或 IAM 获取了用户/服务的 STS Token（由 `AssumeRole` 产生）；
   - KBS 在即将返回敏感密钥前，调用 `POST /authz/evaluate`，将：
     - STS Token（身份 + 角色）；
     - 资源 ARN（如某个 Key）；
     - 从 TNG/AS 获得的 Attestation Claims（映射到 `env.*`）；
     - 以及请求自身信息（来源 IP、通道类型）等，
     一并提交给 IAM。

5. **IAM 策略评估**
   - IAM 在 Policy Engine 中综合考虑：
     - `principal.*`（调用主体是谁、属于哪个 Account）；
     - `env.*`（连接对端是否来自预期的 TEE 环境、测量值是否合法）；
     - `resource.*`（密钥属于谁、是否高敏）；
     - `request.*`（操作为 `kbs:GetKey`、来源 IP、访问路径等）；
   - 若满足策略条件，则返回 `{ "allowed": true }`，否则 `{ "allowed": false }`。

6. **KBS → 应用容器**
   - 若授权通过，KBS 将密钥通过 TNG 隧道回传给应用；
   - 整个过程对应用而言只是一条“HTTP 调用”，但实际在网络层已受到 TNG + AS 的保护，在授权层受到 IAM 的控制。

在这个过程中：

- **TNG + AS**：负责确保“连到 KBS/Gateway 的这条链路对端，是某个通过远程证明验证的可信环境”；
- **IAM**：负责在此基础上，对具体 Action/Resource 做细粒度权限裁决；
- **KBS**：负责密钥和机密数据的持有与下发，实现数据面的实际访问控制。

---

## 8. 小结

通过将 Attestation Token、KBS 资源、TNG 用户授权和 guest-components 运行时身份统一在 IAM 的“身份 + 资源 + 策略”模型下：

- **安全属性**：可在策略中表达非常细粒度的要求（例如“只有特定测量值的 TEE、来自某账号的运行时、代表某个用户，在某个时间段内才可访问某个密钥”）。
- **可运营性**：授权与回收可以通过修改 Role/Policy 实现，而不需要改动 KBS/TNG/guest-components 的核心代码。
- **可扩展性**：未来接入更多服务或资源类型时，只需要注册新的 ResourceType 和 Action，将其接入 IAM 的 Evaluate 流程即可。

这套联动方案既保持各组件的职责边界，又通过 IAM 提供统一可控的授权平面，是整个 Trustee 体系在多方协作场景下的关键设计。***

