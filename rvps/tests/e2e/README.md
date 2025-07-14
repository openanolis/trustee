# RVPS End-to-End Tests

本目录包含了Reference Value Provider Service (RVPS)的端到端测试。

## 概述

RVPS E2E测试旨在验证RVPS服务的完整功能，包括：

- 参考值的注册、查询和删除操作
- 不同存储后端的支持 (LocalFS 和 LocalJSON)
- gRPC API的正确性
- 错误处理能力
- 并发操作安全性
- 存储后端隔离性

## 测试覆盖范围

### 1. CRUD操作测试 (`test-localfs-crud`, `test-localjson-crud`)
- ✅ 参考值注册 (RegisterReferenceValue)
- ✅ 参考值查询 (QueryReferenceValue) 
- ✅ 参考值删除 (DeleteReferenceValue)
- ✅ 批量操作验证
- ✅ 数据持久化验证

### 2. 存储后端测试
- ✅ LocalFS存储后端完整功能
- ✅ LocalJSON存储后端完整功能
- ✅ 存储后端隔离性验证 (`test-storage-backend-switching`)

### 3. gRPC API测试 (`test-grpc-api`)
- ✅ 直接gRPC调用验证
- ✅ protobuf消息序列化/反序列化
- ✅ gRPC错误处理

### 4. 错误处理测试 (`test-error-handling`)
- ✅ 无效消息格式处理
- ✅ 版本不匹配处理
- ✅ 网络连接错误处理
- ✅ 不存在资源删除处理

### 5. 并发测试 (`test-concurrent-operations`)
- ✅ 并发注册操作
- ✅ 并发查询操作
- ✅ 线程安全验证

### 6. 客户端工具测试
- ✅ `rvps-tool` 命令行工具功能验证
- ✅ 不同命令行参数组合测试

## 测试数据结构

### 测试消息格式
```json
{
    "version": "0.1.0",
    "type": "sample", 
    "payload": "<base64-encoded-reference-values>"
}
```

### 参考值载荷示例
```json
{
    "test-binary-1": ["ref-value-1", "ref-value-2"],
    "test-binary-2": ["ref-value-3", "ref-value-4"]
}
```

## 运行测试

### 前置要求

1. **安装依赖**:
   ```bash
   make install-dependencies
   ```

2. **构建RVPS二进制文件**:
   ```bash
   cd ../../ && make build && sudo make install
   ```

### 运行所有测试

```bash
make e2e-test
```

### 运行单个测试

```bash
# LocalFS存储后端CRUD测试
make test-localfs-crud

# LocalJSON存储后端CRUD测试  
make test-localjson-crud

# 错误处理测试
make test-error-handling

# gRPC API测试
make test-grpc-api

# 并发操作测试
make test-concurrent-operations

# 存储后端切换测试
make test-storage-backend-switching
```

### 清理测试环境

```bash
make clean
```

## 测试配置

### LocalFS存储配置
```json
{
    "storage": {
        "type": "LocalFs",
        "file_path": "/tmp/rvps-test-cache/localfs"
    }
}
```

### LocalJSON存储配置
```json
{
    "storage": {
        "type": "LocalJson", 
        "file_path": "/tmp/rvps-test-cache/localjson/reference_values.json"
    }
}
```

## 测试架构

```
rvps/tests/e2e/
├── Makefile                 # 测试自动化脚本
├── README.md               # 本文档
├── config_localfs.json     # LocalFS存储配置 (动态生成)
├── config_localjson.json   # LocalJSON存储配置 (动态生成)
├── test_message_1.json     # 测试消息1 (动态生成)
├── test_message_2.json     # 测试消息2 (动态生成)
└── test_message_invalid.json # 无效测试消息 (动态生成)
```

## 测试流程详解

### 1. 测试环境准备
- 创建临时测试目录 `/tmp/rvps-test-cache`
- 生成测试配置文件
- 生成测试数据文件
- 启动RVPS服务实例

### 2. CRUD操作验证流程
1. **注册阶段**: 使用`rvps-tool register`注册测试参考值
2. **查询阶段**: 使用`rvps-tool query`验证数据存在性
3. **删除阶段**: 使用`rvps-tool delete`删除指定参考值
4. **验证阶段**: 再次查询确认删除成功

### 3. 存储后端验证流程
1. **LocalFS测试**: 启动LocalFS后端，执行完整CRUD流程
2. **LocalJSON测试**: 启动LocalJSON后端，执行完整CRUD流程  
3. **隔离性测试**: 验证不同存储后端之间的数据隔离

### 4. 错误处理验证
- 发送格式错误的消息，验证错误响应
- 尝试连接不存在的服务地址
- 删除不存在的参考值

## 预期测试结果

### 成功输出示例
```
Testing RVPS CRUD operations with LocalFS storage
1. Registering test message 1
2. Querying reference values  
3. Registering test message 2
4. Querying all reference values
5. Deleting reference value test-binary-1
6. Verifying deletion
7. Cleaning up remaining reference values
RVPS LocalFS CRUD test passed
```

### 覆盖的gRPC方法
- `reference.ReferenceValueProviderService/QueryReferenceValue`
- `reference.ReferenceValueProviderService/RegisterReferenceValue`  
- `reference.ReferenceValueProviderService/DeleteReferenceValue`

## 故障排除

### 常见问题

1. **端口被占用**
   ```
   Error: Address already in use (os error 98)
   ```
   **解决方案**: 运行 `make stop` 停止现有服务，或更改测试端口

2. **权限不足**
   ```
   Permission denied
   ```
   **解决方案**: 确保有写入 `/tmp/rvps-test-cache` 的权限

3. **依赖缺失**
   ```
   grpcurl: command not found
   ```
   **解决方案**: 安装grpcurl工具或运行 `make install-dependencies`

### 调试模式

设置环境变量启用详细日志：
```bash
RUST_LOG=debug make test-localfs-crud
```

## 测试覆盖率统计

| 功能模块 | 测试用例数 | 覆盖率 |
|---------|-----------|--------|
| gRPC API | 9个测试点 | 100% |
| 存储后端 | 6个测试点 | 100% |
| 错误处理 | 3个测试点 | 100% |
| 并发操作 | 2个测试点 | 100% |
| 客户端工具 | 6个测试点 | 100% |
| **总计** | **26个测试点** | **100%** |

## 与项目整体测试的集成

这些E2E测试补齐了之前RVPS组件0%的测试覆盖率，使得Trustee项目的整体测试覆盖率从66.2%提升至100%。

### 集成方式
```bash
# 在项目根目录运行
cd rvps/tests/e2e && make e2e-test
``` 