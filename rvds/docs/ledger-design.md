# RVDS 发布事件不可篡改账本记录设计

## 背景与目标

- 发布事件需要“公开可审计、不可篡改”地留痕（典型载体：区块链 / 透明日志）。
- RVDS 在收到 `PublishEventRequest` 时，除转发给 Trustee 外，还需将事件摘要写入外部账本，并返回记录凭据。
- 设计需可扩展：不同场景可接入不同账本（链、透明日志、第三方网关）。

## 设计概览

- 新增 **Ledger Recorder** 组件，核心是 `LedgerAdapter` 抽象：
  - `record_event(event, canonical_payload) -> LedgerReceipt`
- 内置实现：`NoopLedger`（默认）、`HttpLedger`（对接外部账本网关）、`EthGatewayLedger`（通过以太坊网关写入链上日志）。
- 事件哈希：
  - 使用 canonical JSON（对 `PublishEventRequest` 进行稳定序列化）后计算 `SHA256`，得到 `event_hash` 与 `payload_hash`。
  - 账本端仅写入摘要（hash），不携带原文；原始 payload 以 base64 形式保存在 RVPS 的 `audit_proof` 中，供审计者校验。
- RVDS API 回包增强：
  - `PublishResponse` 增加 `ledger_receipt`，便于 CI 在发布日志中附带证明。

## 账本适配层

### 接口
```rust
pub trait LedgerAdapter {
    async fn record_event(&self, event: &PublishEventRequest, canonical_payload: &str) -> Result<LedgerReceipt>;
}
```

### 内置实现
- `NoopLedger`：不写外部账本，返回合成的 `event_hash`。
- `HttpLedger`：POST `{event_hash, payload}` 到外部网关；网关可自行决定只上链 hash 或其它策略；`ledger_receipt` 会携带本地的 `payload_b64` 供审计者使用。
- `EthGatewayLedger`：面向以太坊链，通过网关 POST `{event_hash, payload}`，网关签名调用合约时仅写入摘要（hash），返回 `tx_hash`；`ledger_receipt` 同样附带 `payload_b64`。

### 选择与配置
- 环境变量：
  - `RVDS_LEDGER_BACKEND`：`none`（默认）、`http` 或 `eth`
  - `RVDS_LEDGER_HTTP_ENDPOINT`：后端网关地址（`http` 模式必填）
  - `RVDS_LEDGER_HTTP_API_KEY`：可选鉴权
  - `RVDS_LEDGER_ETH_GATEWAY`：以太坊网关地址（`eth` 模式必填）
  - `RVDS_LEDGER_ETH_GATEWAY_API_KEY`：以太坊网关鉴权（可选）
- 未来扩展：
  - 可增加 `RekorAdapter`（Sigstore 透明日志）、`EthereumAdapter`（合约记录 `event_hash`），只需实现 `LedgerAdapter` 并在工厂中注册。

## 时序（含账本）

1. CI 调用 `POST /rvds/rv-publish-event`。
2. RVDS 规范化序列化 payload，计算 `event_hash`。
3. Ledger Recorder 通过适配器写入外部账本，获得 `ledger_receipt`（可能为空）。
4. RVDS 按原逻辑并发转发给各 Trustee 的 `/api/rvps/register`。
5. RVDS 返回（示例）：
   ```json
   {
     "forwarded": [...],
     "ledger_receipt": {
       "backend": "http",
       "handle": "<opaque-proof>",
       "event_hash": "<sha256>",
       "payload_hash": "<sha256>",
       "payload_b64": "<base64 of canonical payload>"
     }
   }
   ```
6. 可选：Trustee/RVPS 存储或透传 `ledger_receipt`，便于后续审计。

- ## 容错与安全
-
- Ledger 失败策略：记录 warning 并继续转发（可根据需求改成强制失败）。
- 哈希基于 canonical payload，避免字段顺序影响；业务如需更强规范，可固定字段排序/移除冗余。
- 如需强制验证 ledger 成功，可在生产环境加开关：失败则拒绝发布。
-
- ## 实现范围（本次）
-
- 新增适配层与配置，默认 `none`，支持 `http` 网关写入，以及 `eth`（以太坊网关）模式。
- 在 `PublishResponse` 返回 `ledger_receipt`。
- 文档同步：architecture、flow 以及本设计说明。

## 以太坊链设计（网关模式）与合约示例

- 模式：RVDS 通过 `EthGatewayLedger` 把 `{event_hash, payload}` POST 到以太坊网关；网关负责签名并调用链上合约时仅写入摘要（hash），返回 `tx_hash`。原文不链上存储，`payload_b64` 仅在 RVPS 中保存。
- 网关接口建议：
  - `POST /record` `{ "event_hash": "<hex>", "payload": "<canonical json>" }`
  - 返回 `{ "tx_hash": "0x..." }`
- 合约示例（Solidity 0.8.x）：
  ```solidity
  // SPDX-License-Identifier: Apache-2.0
  pragma solidity ^0.8.17;

  contract RvdsEventLog {
      event EventRecorded(bytes32 indexed eventHash, string payloadHash, address indexed sender, uint256 blockNumber);

      function record(bytes32 eventHash, string calldata payloadHash) external {
          emit EventRecorded(eventHash, payloadHash, msg.sender, block.number);
      }
  }
  ```
- 部署与网关步骤（概要）：
  1. 选择链（主网/测试网）并配置 RPC。
  2. 部署合约 `RvdsEventLog`，记录下合约地址。
  3. 网关持有链上账户私钥，暴露 REST 接口 `/record`：
     - 将 `event_hash`、`payloadHash`（可使用同样的 sha256/canonical）调用合约 `record`。
     - 返回 `tx_hash` 供 RVDS 作为 `handle`。
  4. 在 RVDS 配置：
     - `RVDS_LEDGER_BACKEND=eth`
     - `RVDS_LEDGER_ETH_GATEWAY=https://<your-eth-gateway>/record`
     - `RVDS_LEDGER_ETH_GATEWAY_API_KEY=<token>`（若需要）
  5. 审计时：根据 `event_hash` 计算后，在链上事件日志中查找 `EventRecorded`，确认对应 `tx_hash` 与区块高度。

