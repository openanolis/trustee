# RVDS 部署指南

## 前置条件

- 已安装 Rust 工具链（1.75+）与 Docker（可选）。
- 目标环境可访问各 Trustee Gateway（如 `https://<trustee>:8081`）。
- Release 工作流可调用 RVDS 暴露的 HTTP 地址。

## 配置项

环境变量：

- `RVDS_LISTEN_ADDR`：监听地址，默认 `0.0.0.0:8090`
- `RVDS_DATA_DIR`：订阅持久化目录，默认 `data/rvds`
- `RVDS_FORWARD_TIMEOUT_SECS`：转发超时秒数，默认 `10`
- `RVDS_LEDGER_BACKEND`：`none`（默认）、`http`、`eth`
- `RVDS_LEDGER_HTTP_ENDPOINT` / `RVDS_LEDGER_HTTP_API_KEY`：账本网关（http）配置
- `RVDS_LEDGER_ETH_GATEWAY` / `RVDS_LEDGER_ETH_GATEWAY_API_KEY`：以太坊网关配置
- `RUST_LOG`：日志等级，如 `info,rvds=debug`

## 源码构建运行

```bash
cd /root/design/trustee/rvds
cargo run --release
```

## Docker 镜像构建

```bash
cd /root/design/trustee
docker build -f Dockerfile.rvds -t rvds:latest .
```

运行：

```bash
docker run -it --rm \
  -e RVDS_LISTEN_ADDR=0.0.0.0:8090 \
  -e RVDS_DATA_DIR=/var/lib/rvds \
  -e RVDS_FORWARD_TIMEOUT_SECS=10 \
  -p 8090:8090 \
  -v /path/to/data:/var/lib/rvds \
  rvds:latest
```

## 订阅与发布示例

注册 Trustee：

```bash
curl -k -X POST http://localhost:8090/rvds/subscribe/trustee \
  -H 'Content-Type: application/json' \
  -d '{"trustee_url":["https://127.0.0.1:8081"]}'
```

发布事件（CI 工作流中调用）：

```bash
curl -k -X POST http://localhost:8090/rvds/rv-publish-event \
  -H 'Content-Type: application/json' \
  -d @payload.json
```

其中 `payload.json`：

```json
{
  "artifact_type": "rpm",
  "slsa_provenance": ["...base64 of intoto jsonl...", "..."],
  "artifacts_download_url": ["https://example.com/build.rpm"]
}
```

## 与 CI 工作流对接要点

- 在 release workflow 中生成 `PublishEventRequest`，通过 `curl`/`gh api` 等 POST 到 RVDS。
- RVDS 会自动并发转发到已注册的 Trustee；失败结果会返回在响应中，供重试或告警。
- 若配置了 ledger，RVDS 会在响应和下游 payload 中附带 `audit_proof`（含 event_hash/payload_hash/payload_b64、tx 句柄等），便于 RVPS/审计使用。


