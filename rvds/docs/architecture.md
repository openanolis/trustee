# RVDS（Reference Value Distribution Service）架构设计

本文档描述 RVDS 的设计目标、组件划分、接口契约以及与现有 Trustee/RVPS 的集成方式，便于后续实现、运维和扩展。

## 设计目标

- 接收 CI/CD 在发布时推送的制品发布事件（包含 SLSA provenance 与制品下载链接）。
- 维护已订阅的 Trustee 列表，将发布事件转发到其 RVPS 注册接口。
- 提供最简可扩展的 API（REST），便于 Workflow 与管理员调用。
- 具备生产可运维性：可配置、可观测（日志）、可恢复（订阅列表持久化）。

## 逻辑组件

- **HTTP API（Actix-web）**：暴露 `/rvds/*` 接口，负责参数校验与响应封装。
- **订阅注册表（Subscriber Registry）**：用 `HashSet` 存储已注册的 Trustee 基址，持久化于 `data/rvds/subscribers.json`。
- **事件转发器（Forwarder）**：接收发布事件后，构造 RVPS 期望的 `message` 包裹并并发调用各 Trustee 的 `/api/rvps/register`。
- **账本记录器（Ledger Recorder）**：对 `PublishEventRequest` 做规范化哈希，写入外部不可篡改账本（默认 noop，可配置 HTTP / 以太坊网关），返回记录凭据，并将审计凭据随 payload 一并下发。
- **配置与启动器（Config / Bootstrap）**：从环境变量加载监听地址、数据目录、下游调用超时等参数。

## 数据模型

- **SubscribeRequest**
  ```json
  { "trustee_url": ["https://127.0.0.1:8081", "..."] }
  ```
- **PublishEventRequest**
  ```json
  {
    "artifact_type": "rpm",
    "slsa_provenance": ["..."],      // 多个 provenance（原文或 base64），数组形式
    "artifacts_download_url": ["https://...rpm"],
    "audit_proof": {                 // 可选，账本回执
      "backend": "ethereum-gateway",
      "handle": "0x<tx_hash>",
      "event_hash": "<sha256(canonical payload)>",
      "payload_hash": "<sha256(payload)>",
      "payload_b64": "<base64 of payload>"
    }
  }
  ```
- **转发给 RVPS 的请求**
  ```json
  {
    "message": "{\"version\":\"0.1.0\",\"type\":\"slsa\",\"payload\":\"{...PublishEventRequest...}\"}"
  }
  ```
  - `payload` 是 `PublishEventRequest` 的 JSON 字符串。

## 接口契约

- `POST /rvds/subscribe/trustee`
  - 功能：注册/追加 Trustee 基址，去重持久化。
  - 返回：已新增的地址列表。
- `POST /rvds/rv-publish-event`
  - 功能：校验事件并转发到全部 Trustee。
  - 返回：每个 Trustee 的投递结果（成功/失败与错误信息），以及可选的 ledger 记录凭据。

## 工作流程

1. 管理员/自动化调用 `/rvds/subscribe/trustee` 追加 Trustee 列表。
2. Release 工作流完成构建与 SLSA 生成后，调用 `/rvds/rv-publish-event` 推送事件。
3. RVDS 将事件封装为 `RVPS message`，并发调用每个 Trustee Gateway 的 `/api/rvps/register`。
4. Trustee 侧 RVPS 使用 `slsa` extractor 校验 provenance、提取制品哈希并入库。

## 扩展点

- **提取器类型**：`type` 字段可扩展为其它 provenance 解析器，与 RVPS extractor 对应。
- **存储后端**：当前使用文件持久化，未来可替换为数据库或 KV。
- **鉴权**：目前接口开放，可按需在 Actix middleware 中增加鉴权/限流。
- **重试策略**：当前单次调用 + 超时，可按需增加重试与死信队列。

## 运行时与配置

- 环境变量
  - `RVDS_LISTEN_ADDR`：HTTP 监听地址，默认 `0.0.0.0:8090`
  - `RVDS_DATA_DIR`：订阅持久化目录，默认 `data/rvds`
  - `RVDS_FORWARD_TIMEOUT_SECS`：下游请求超时，默认 `10`
- 日志：使用 `env_logger`，可通过 `RUST_LOG` 配置。

## 安全与健壮性

- URL 规范化：去除尾部斜杠，避免重复注册。
- 并发隔离：下游调用使用超时保护，单目标失败不会阻塞整体流程。
- 持久化恢复：服务重启后自动读取 `subscribers.json` 恢复订阅。


