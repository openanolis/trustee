# Trustee Gateway

Trustee Gateway 是 Trustee 项目的重要组件，它作为 KBS（Key Broker Service）和 RVPS（Reference Value Provider Service）等后端服务的 API 网关。Gateway 提供了统一的接入点、访问控制和审计功能，简化了 Trustee 系统的整体架构。

## 功能特性

- **统一接入点**：为 KBS 和 RVPS 等后端服务提供统一的 API 接入点
- **请求转发**：智能代理请求到相应的后端服务
- **后端访问控制**：KBS 校验管理员 JWT 和证明 token；Gateway 自身接口及 AS 管理接口需由部署侧访问控制保护
- **审计日志**：记录关键操作，包括证明请求和资源访问
- **资源管理**：将资源、策略和参考值操作转发到权威后端，不维护本地状态副本
- **健康检查**：监控后端服务的可用性

## 架构设计

```
┌─────────────┐      ┌─────────────────┐      ┌─────────────┐
│             │      │                 │      │             │
│  客户端请求  ├─────▶│  Trustee Gateway ├─────▶│  KBS 服务   │
│             │      │                 │      │             │
└─────────────┘      └────────┬────────┘      └─────────────┘
                              │
                              │               ┌─────────────┐
                              │               │             │
                              └──────────────▶│  RVPS 服务  │
                                              │             │
                                              └─────────────┘
```

Trustee Gateway 包含以下主要模块：

- **代理模块**：负责请求转发到后端服务
- **处理器模块**：处理各类API请求（KBS、RVPS、审计等）
- **持久化模块**：仅存储审计和实例心跳；单副本可使用 SQLite，多副本使用 MySQL
- **中间件模块**：提供日志记录、CORS 等通用功能，不代替部署侧用户鉴权

RVPS 管理请求实际经过 Gateway -> KBS -> AS -> RVPS；Gateway 的直接 RVPS
gRPC 客户端用于健康检查。AS HTTP 接口直接转发到 RESTful AS。

完整接口、请求格式、认证和缓存边界见 [API 文档](trustee_gateway_api.md)。
完整真实服务 API 测试见 [E2E 测试说明](test/e2e/README.md)：CI 覆盖 45 个操作、
5 种存储组合，以及解释器 / Regorus VM 两种策略引擎。

## 配置说明

Gateway 通过 `config.yaml` 文件进行配置，主要配置项包括：

```yaml
server:
  host: "0.0.0.0"  # 服务监听地址
  port: 8081       # 服务监听端口

kbs:
  url: "http://kbs:8080"  # KBS 服务地址

rvps:
  grpc_addr: "rvps:50003"  # RVPS gRPC 服务地址

database:
  type: "sqlite"  # 数据库类型
  require_shared: false  # 多副本部署设为 true，并使用 mysql
  path: "/app/data/trustee-gateway.db"  # 数据库文件路径

logging:
  level: "debug"  # 日志级别
```

多副本部署时使用共享 MySQL，并通过 Secret 注入 DSN：

```yaml
database:
  type: "mysql"
  require_shared: true
  max_open_conns: 20
  max_idle_conns: 5
  conn_max_lifetime: "1h"
```

容器环境变量 `TRUSTEE_GATEWAY_DATABASE_DSN` 的优先级高于配置文件中的
`database.dsn`。当 `require_shared` 为 `true` 时，Gateway 会拒绝 SQLite，
避免多副本各自维护不一致的本地审计和心跳数据。

## API 端点

Gateway 提供以下主要 API 端点：

### KBS 相关 API

- `/api/kbs/v0/auth` - KBS 认证
- `/api/kbs/v0/attest` - 远程证明
- `/api/kbs/v0/attestation-policy` - 证明策略管理
- `/api/kbs/v0/resource-policy` - 资源策略管理
- `/api/kbs/v0/resource/:repository/:type/:tag` - 资源管理
- `/api/kbs/v0/resources` - 资源列表
- `/api/kbs/v0/resource/pubkey` - 获取客户端加密公钥
- `/api/kbs/v0/resource/reload` - 热加载托管密钥
- `/api/kbs/v0/resource/rewrap` - 使用当前主密钥重包资源
- `/api/kbs/v0/resource/rotate` - 一次性轮转托管密钥并重包资源

### RVPS 相关 API

- `/api/rvps/*` - RVPS 服务代理

### 审计 API

- `/api/audit/attestation` - 证明记录查询
- `/api/audit/resources` - 资源访问记录查询

### 健康检查 API

- `/api/health` - Gateway 健康检查
- `/api/services-health` - 后端服务健康检查

## 构建与运行

### 本地构建

```bash
go build -o trustee-gateway ./cmd/server
```

### Docker 构建

```bash
docker build -t trustee-gateway:latest -f Dockerfile.trustee-gateway .
```

### 运行

使用 docker-compose 启动整个 Trustee 系统：

```bash
docker-compose up -d
```

单独运行 Gateway：

```bash
docker run -p 8081:8081 -v $(pwd)/config.yaml:/app/config.yaml trustee-gateway:latest
```

## 数据存储

Trustee Gateway 使用数据库存储以下信息：

- 证明策略
- 资源策略
- 审计记录

单副本默认使用 SQLite，数据库位于 `/app/data/trustee-gateway.db`，可通过配置
文件修改。多副本必须改用共享 MySQL，并设置 `database.require_shared: true`；
连接 DSN 建议通过 Kubernetes Secret 注入 `TRUSTEE_GATEWAY_DATABASE_DSN`。

## 日志

Gateway 使用 logrus 进行日志记录，日志级别可在配置文件中设置。在容器环境中，可通过以下命令查看日志：

```bash
docker logs trustee-gateway
```

## 许可证

与 Trustee 项目其他组件一致，遵循 Apache 2.0 许可证。
