# Trustee Gateway 安装使用指南

本文档详细说明如何安装、配置和使用 Trustee Gateway。

## 前提条件

- Go 1.18 或更高版本
- Docker 和 Docker Compose (可选，用于容器化部署)
- 访问后端服务的网络连接 (KBS 和 RVPS)

## 安装方法

### 方法一：从源码构建

1. 克隆项目代码

```bash
git clone https://github.com/openanolis/trustee.git
cd trustee
```

2. 构建网关服务

```bash
cd trustee-gateway
go build -o bin/trustee-gateway ./cmd/server
```

3. 创建配置文件

复制示例配置文件并根据需要进行修改：

```bash
cp config.yaml config.local.yaml
```

4. 运行服务

```bash
mkdir -p data
./bin/trustee-gateway -config config.local.yaml
```

### 方法二：使用 Docker

1. 构建 Docker 镜像

```bash
docker build -t trustee-gateway:latest -f Dockerfile.trustee-gateway .
```

2. 创建持久化存储目录

```bash
mkdir -p data
```

3. 运行容器

```bash
docker run -d --name trustee-gateway \
  -p 8081:8081 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v $(pwd)/data:/app/data \
  trustee-gateway:latest
```

### 方法三：使用 Docker Compose

如果您想一次性部署完整的 Trustee 系统（包括 KBS、RVPS 和 Gateway），可以使用 Docker Compose：

```bash
docker-compose up -d
```

## 配置详解

### 主要配置项

编辑 `config.yaml` 文件配置以下参数：

```yaml
server:
  host: "0.0.0.0"  # 监听地址，默认监听所有网络接口
  port: 8081       # 监听端口，默认 8081

kbs:
  url: "http://kbs:8080"  # KBS 服务 URL，确保 Gateway 可以访问

rvps:
  grpc_addr: "rvps:50003"  # RVPS gRPC 服务地址，用于直接 gRPC 通信

database:
  type: "sqlite"                         # 数据库类型，目前支持 sqlite
  path: "/app/data/trustee-gateway.db"   # 数据库文件路径

logging:
  level: "debug"  # 日志级别: debug, info, warn, error
```

### 高级配置

对于生产环境，建议进行以下配置：

1. 启用 HTTPS

可以在前端使用 Nginx 或其他反向代理配置 HTTPS。

2. 调整日志级别

生产环境建议使用 `info` 或 `warn` 级别以减少日志量：

```yaml
logging:
  level: "info"
```

## 验证安装

安装完成后，可以通过以下方式验证服务是否正常运行：

1. 检查服务状态

```bash
curl http://localhost:8081/api/health
```

预期返回：

```json
{
  "status": "ok"
}
```

2. 检查后端服务连接状态

```bash
curl http://localhost:8081/api/services-health
```

预期返回：

```json
{
  "kbs": "ok",
  "rvps": "ok"
}
```
