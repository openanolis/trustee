# RVDS 全流程逻辑说明

本文覆盖从制品发布到参考值落库的端到端路径，便于研发、运维和审计理解系统行为。

## 角色与组件

- **CI 发布流程**：构建 artifacts，生成 SLSA provenance（参考 guest-components 工作流）。
- **RVDS**：接收发布事件，维护 Trustee 列表，转发到 RVPS。
- **Trustee Gateway**：暴露 `/api/rvps/register` HTTP 入口，桥接到 RVPS gRPC。
- **RVPS**：校验 provenance，提取哈希值并存储参考值。

## 时序

1. **订阅阶段**
   - 管理员调用 `POST /rvds/subscribe/trustee` 注册 Trustee 地址，RVDS 写入 `subscribers.json`。
2. **发布阶段**
   - CI Workflow 完成构建后，生成 `PublishEventRequest`，POST 到 `POST /rvds/rv-publish-event`。
3. **转发阶段**
   - RVDS 将 `PublishEventRequest` 封装为 `RVPS message`：
```json
{
   "message": "{\"version\":\"0.1.0\",\"type\":\"slsa\",\"payload\":\"{...}\"}"
}
```
   - 并发调用每个 Trustee 的 `https://<trustee>/api/rvps/register`。
4. **校验与入库**
   - Trustee Gateway 将请求转给 RVPS gRPC `RegisterReferenceValue`。
   - RVPS 通过 `slsa` extractor：
     - 解析 `payload` 得到 `artifact_type/slsa_provenance[]/artifacts_download_url`。
     - 针对每个 provenance（raw JSON 或 base64 JSON）解析 subject，支持多份 provenance。
     - 抽取 `subject[].digest`（优先 `sha256`），生成 `ReferenceValue`（默认 12 个月有效）。
     - 调用存储接口写入参考值。
5. **消费**
   - 上游（如 AS）调用 RVPS `query_reference_value` 获取可信哈希用于度量验证。

## 失败与补偿

- RVDS 转发失败会在响应中返回失败列表，可由 CI 重试或告警。
- RVPS 校验失败会返回 gRPC 错误；RVDS 会记录 HTTP 非 2xx 但不会阻塞其它 Trustee。
- 订阅持久化在 `subscribers.json`，服务重启后自动恢复，无需重新注册。

## 安全注意

- 建议在生产环境对 RVDS 增加鉴权（如 Token/Header 校验）与 TLS 证书配置。
- RVDS 对下游调用有超时保护（默认 10s），避免单节点拖垮整体发布流程。


