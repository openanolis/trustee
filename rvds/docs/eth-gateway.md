# RVDS 以太坊网关使用指南

> 作用：提供一个具备签名与上链能力的 HTTP 网关，接受 RVDS 的事件摘要请求，调用链上合约 `record(bytes32 eventHash, string payloadHash)`，并返回真实交易哈希。

## 功能

- 端点：`POST /record`
- 请求：
  ```json
  {
    "event_hash": "0x<sha256 hex>",        // 32字节
    "payload": "canonical PublishEventRequest JSON"
  }
  ```
- 响应：
  ```json
  { "tx_hash": "0x<real-ethereum-tx-hash>" }
  ```
- 内部逻辑：
  - 对 payload 做 sha256，作为 `payloadHash`。
  - ABI 编码调用合约 `record(eventHash, payloadHash)`。
  - 使用私钥签名交易并通过 RPC 发送，返回 tx_hash。
  - 默认 gas 200000，gas_price 来自链上 `eth_gasPrice`。

## 启动

```bash
cd /root/design/trustee/rvds
cargo run --bin eth_gateway
```

必需环境变量：
- `ETH_RPC_URL`：以太坊 RPC 地址（可用公用节点或自建节点）
- `ETH_PRIVATE_KEY`：0x 前缀的私钥（用于签名）
- `ETH_CONTRACT_ADDRESS`：已部署的合约地址（示例见下）

可选环境变量：
- `ETH_GATEWAY_LISTEN`：监听地址，默认 `0.0.0.0:8095`
- `ETH_CHAIN_ID`：链 ID，默认 `1`

## 合约示例（Solidity 0.8.x）

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

部署后将合约地址写入 `ETH_CONTRACT_ADDRESS`。

## 与 RVDS 对接

在 RVDS 配置：
- `RVDS_LEDGER_BACKEND=eth`
- `RVDS_LEDGER_ETH_GATEWAY=http://<gateway-host>:8095/record`
- `RVDS_LEDGER_ETH_GATEWAY_API_KEY`（当前未校验，可留空）

RVDS 在 `/rvds/rv-publish-event` 时调用网关，`ledger_receipt.handle` 将包含真实链上 `tx_hash`。

## 生产注意

- 私钥务必放在可信环境，可优先使用 KMS/HSM 管理；当前示例从环境变量读取，仅适用于 PoC。
- 请确认 gas 费、nonce 管理符合预期；当前实现使用链上 `gasPrice`，固定 gas=200000，可按需调整或改为 `eth_estimateGas`。
- 如需鉴权，可在网关增加 API Key/Token 校验，并在 RVDS 设置 `RVDS_LEDGER_ETH_GATEWAY_API_KEY`。 

