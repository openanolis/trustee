# RVDS（Reference Value Distribution Service）

RVDS 是用于分发制品参考值（含 SLSA provenance）的轻量 REST 服务。它接收 CI/CD 发布事件，写入可选的不可篡改账本（如以太坊网关/HTTP 网关），并将事件转发给已注册的 Trustee/RVPS，最终在 RVPS 中存储参考值及审计凭据。

## 功能特性
- 发布事件接收：`POST /rvds/rv-publish-event`，携带 artifact_type、slsa_provenance、下载链接。
- Trustee 订阅管理：`POST /rvds/subscribe/trustee` 去重追加 Trustee 地址。
- 并发转发：将事件包裹为 RVPS message，下发至每个 Trustee 的 `/api/rvps/register`。
- 账本记录（可选）：支持 `none`/`http`/`eth` 网关，写入摘要并返回审计凭据；payload_base64 保存在 RVPS，链上仅存 hash。
- 审计闭环：RVPS ReferenceValue 中可选 `audit_proof`，包含 backend/handle/event_hash/payload_hash/payload_b64，审计者可据此在链上验证摘要、在 RVPS 取原文校验。

## 目录结构（核心）
- `src/`：服务代码（Actix Web、路由、状态管理、ledger 适配器）。
  - `ledger/`：ledger 抽象与实现（noop/http/eth_gateway）。
  - `bin/eth_gateway.rs`：以太坊网关，可将摘要写链。
- `docs/`：架构、流程、ledger 设计、部署、审计指南、eth 网关说明。

## API 摘要
- `POST /rvds/subscribe/trustee`
  - Body: `{"trustee_url": ["https://127.0.0.1:8081", "..."]}`
  - Resp: `{"registered": [...] }`
- `POST /rvds/rv-publish-event`
  - Body (示例):
    ```json
    {
      "artifact_type": "rpm",
      "slsa_provenance": ["...base64 intoto..."],
      "artifacts_download_url": ["https://example.com/a.rpm"]
    }
    ```
  - Resp: `{"forwarded": [...], "ledger_receipt": {...}}`

## 配置（环境变量）
- 基础
  - `RVDS_LISTEN_ADDR`：默认 `0.0.0.0:8090`
  - `RVDS_DATA_DIR`：默认 `data/rvds`
  - `RVDS_FORWARD_TIMEOUT_SECS`：默认 `10`
- Ledger
  - `RVDS_LEDGER_BACKEND`: `none` | `http` | `eth`
  - `RVDS_LEDGER_HTTP_ENDPOINT` / `RVDS_LEDGER_HTTP_API_KEY`
  - `RVDS_LEDGER_ETH_GATEWAY` / `RVDS_LEDGER_ETH_GATEWAY_API_KEY`
- 日志
  - `RUST_LOG`：如 `info,rvds=debug`

## 构建与运行
```bash
cd /root/design/trustee/rvds
cargo run --release
```

## Docker
```bash
cd /root/design/trustee
docker build -f Dockerfile.rvds -t rvds:latest .
docker run -it --rm \
  -e RVDS_LISTEN_ADDR=0.0.0.0:8090 \
  -e RVDS_DATA_DIR=/var/lib/rvds \
  -e RVDS_FORWARD_TIMEOUT_SECS=10 \
  -p 8090:8090 \
  -v /path/to/data:/var/lib/rvds \
  rvds:latest
```

## 以太坊网关（摘要上链）
- 位置：`src/bin/eth_gateway.rs`
- 需求环境：`ETH_RPC_URL`、`ETH_PRIVATE_KEY`、`ETH_CONTRACT_ADDRESS`（`record(bytes32,string)` 事件日志合约）
- 行为：接收 `{event_hash, payload}`，上链仅写 payload_hash，返回 `tx_hash`；原文不上链。

## 审计说明
- RVPS 的 ReferenceValue 可带 `audit_proof`（可选）：`backend/handle/event_hash/payload_hash/payload_b64`。
- 审计者流程：从 RVPS 取 `payload_b64` 解码重算 hash，对比 `audit_proof.payload_hash`；链上查 `tx_hash` 的事件，核对 eventHash/payloadHash。
- 详见 `docs/audit-guide.md`。

## 文档索引
- `docs/architecture.md`：架构设计
+- `docs/flow.md`：端到端流程
- `docs/ledger-design.md`：账本设计与适配
- `docs/deployment.md`：部署与配置
- `docs/eth-gateway.md`：以太坊网关使用
- `docs/audit-guide.md`：第三方审计手册

## 注意事项
- Ledger/Audit 可选，未配置时字段缺省保持兼容。
- 上链仅写 hash，payload_b64 由 RVPS 存储；

