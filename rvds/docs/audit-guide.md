# 第三方审计操作手册（RVDS + RVPS + 以太坊账本）

本手册指导审计者仅凭 RVPS 返回的参考值（含审计字段）完成端到端验证，确认 RVDS 发布事件已被写入不可篡改账本（以太坊为例），并与 RVPS 内的参考值一致。账本侧仅写入摘要（hash），原文由 RVPS 的 `audit_proof.payload_b64` 提供。

## 前提信息
- RVPS 查询到的 `ReferenceValue`，其中可选字段 `audit_proof`：
  ```json
  {
    "name": "...",
    "hash-value": [...],
    "audit_proof": {
      "backend": "ethereum-gateway",
      "handle": "0x<tx_hash>",
      "event_hash": "<sha256 of canonical PublishEventRequest>",
      "payload_hash": "<sha256 of payload>",
      "payload_b64": "<base64 of canonical payload>"
    }
  }
  ```
- RVDS 账本记录：在 ledger_receipt 中会返回与 `audit_proof` 对应的字段。
- 合约地址与链信息：`ETH_CONTRACT_ADDRESS`，链 ID，RPC/浏览器入口。

## 步骤 1：本地重算并校验摘要
1. 从 RVPS 返回的 `audit_proof.payload_b64` 解码得到 canonical `PublishEventRequest` JSON。
2. 本地计算：
   - `sha256(payload)` → 对比 `payload_hash`。
   - `sha256(canonical payload)` → 对比 `event_hash`。
   若不一致，审计失败。

## 步骤 2：链上验证交易与事件
1. 取 `handle`（`tx_hash`），在浏览器或本地节点查询：
   - 浏览器：输入 tx_hash。
   - 节点：`eth_getTransactionReceipt <tx_hash>`.
2. 确认交易成功，找到来自合约 `RvdsEventLog` 的 `EventRecorded` 事件。
3. 解码事件参数（浏览器通常自动解码）：
   - `eventHash` (bytes32) 应等于 `audit_proof.event_hash`。
   - 第二个参数存储的是 `payloadHash`（摘要上链），应等于 `audit_proof.payload_hash`。

## 步骤 3：对照 RVPS 参考值
1. 从 `payload` 中的 `slsa_provenance` 解析 `subject[].digest`（和 RVPS 逻辑一致）。
2. 确认解析出的制品哈希与 RVPS 返回的 `hash-value` 完全匹配。
3. 如有多份参考值（多个 subject），逐一对应。

## 命令行示例
假设已拿到 `tx_hash`、`event_hash`、`payload_hash`、`payload_b64`：

```bash
# 1) 查询交易（需已配置 ETH_RPC_URL）
curl -s -X POST "$ETH_RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"eth_getTransactionReceipt",
    "params":["<tx_hash>"],
    "id":1
  }' | jq .

# 2) 解析 logs，确认事件里 eventHash == audit_proof.event_hash，payloadHash == audit_proof.payload_hash
# 3) 解码 RVPS 提供的 payload_b64 并重算 hash
echo "<payload_b64_from_rvps>" | base64 -d > payload.json
PAYLOAD_HASH_LOCAL=$(sha256sum payload.json | awk '{print $1}')
echo "local payload hash: $PAYLOAD_HASH_LOCAL"
# 对比 audit_proof.payload_hash / event_hash
```

## 浏览器快速校验
1. 打开区块浏览器，输入 `tx_hash`。
2. 在 Logs/Events 中找到 `EventRecorded`：
   - `eventHash` 对比 `audit_proof.event_hash`。
   - data/decoded payloadHash 对比 `audit_proof.payload_hash`。
   - 原文由 RVPS 的 `payload_b64` 提供，在本地解码后重算哈希比对。

## 注意事项与影响
- 账本只写 hash，原文不上链；RVPS 存储 payload_b64 供审计端重算哈希。
- `audit_proof` 可选，未开启账本时保持兼容（字段缺失不影响现有接口）。
- 若使用其它账本（如 Rekor），在 `audit_proof.backend/handle` 写入对应证明，验证时使用相应工具；结构不变。

