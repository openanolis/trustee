#!/bin/bash

# 审计清理功能集成测试脚本
# 此脚本测试审计日志清理功能在实际环境中的运行效果

set -e

# 配置变量
GATEWAY_URL="http://localhost:8080"
CONFIG_FILE="config_test.yaml"
DB_FILE="test_audit_cleanup.db"
LOG_FILE="audit_cleanup_test.log"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 清理函数
cleanup() {
    log_info "清理测试环境..."
    if [ -f "$DB_FILE" ]; then
        rm -f "$DB_FILE"
    fi
    if [ -f "$CONFIG_FILE" ]; then
        rm -f "$CONFIG_FILE"
    fi
    if [ -f "$LOG_FILE" ]; then
        rm -f "$LOG_FILE"
    fi
    # 如果gateway进程在运行，停止它
    if [ ! -z "$GATEWAY_PID" ]; then
        kill $GATEWAY_PID 2>/dev/null || true
        wait $GATEWAY_PID 2>/dev/null || true
    fi
}

# 设置退出时清理
trap cleanup EXIT

# 创建测试配置文件
create_test_config() {
    log_info "创建测试配置文件..."
    cat > "$CONFIG_FILE" << EOF
server:
  host: "localhost"
  port: 8081

kbs:
  url: "http://localhost:8080"

attestation_service:
  url: "http://localhost:50005"

rvps:
  grpc_addr: "localhost:50003"

database:
  type: "sqlite"
  path: "$DB_FILE"

logging:
  level: "debug"

audit:
  max_records: 5
  retention_days: 1
  cleanup_interval_hours: 1
EOF
}

# 启动gateway服务
start_gateway() {
    log_info "启动gateway服务..."
    RUST_LOG=debug ../gateway -config "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &
    GATEWAY_PID=$!
    
    # 等待服务启动
    log_info "等待服务启动..."
    for i in {1..30}; do
        if curl -s "$GATEWAY_URL/health" > /dev/null 2>&1; then
            log_info "Gateway服务已启动"
            return 0
        fi
        sleep 1
    done
    
    log_error "Gateway服务启动失败"
    return 1
}

# 生成测试数据
generate_test_data() {
    log_info "生成测试审计数据..."
    
    # 使用sqlite3直接插入测试数据
    sqlite3 "$DB_FILE" << EOF
-- 创建表（如果不存在）
CREATE TABLE IF NOT EXISTS attestation_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME,
    client_ip TEXT,
    session_id TEXT,
    request_body TEXT,
    claims TEXT,
    status INTEGER,
    successful BOOLEAN,
    timestamp DATETIME,
    source_service TEXT
);

CREATE TABLE IF NOT EXISTS resource_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME,
    client_ip TEXT,
    session_id TEXT,
    repository TEXT,
    type TEXT,
    tag TEXT,
    method TEXT,
    status INTEGER,
    successful BOOLEAN,
    timestamp DATETIME
);

-- 插入旧数据（3天前）
INSERT INTO attestation_records (created_at, updated_at, client_ip, session_id, request_body, claims, status, successful, timestamp, source_service)
VALUES 
    (datetime('now'), datetime('now'), '127.0.0.1', 'old-session-1', 'old-request-1', 'old-claims-1', 200, 1, datetime('now', '-3 days'), 'kbs'),
    (datetime('now'), datetime('now'), '127.0.0.1', 'old-session-2', 'old-request-2', 'old-claims-2', 200, 1, datetime('now', '-3 days'), 'kbs'),
    (datetime('now'), datetime('now'), '127.0.0.1', 'old-session-3', 'old-request-3', 'old-claims-3', 200, 1, datetime('now', '-3 days'), 'kbs');

INSERT INTO resource_requests (created_at, updated_at, client_ip, session_id, repository, type, tag, method, status, successful, timestamp)
VALUES 
    (datetime('now'), datetime('now'), '127.0.0.1', 'old-session-1', 'old-repo-1', 'secret', 'old-tag-1', 'GET', 200, 1, datetime('now', '-3 days')),
    (datetime('now'), datetime('now'), '127.0.0.1', 'old-session-2', 'old-repo-2', 'secret', 'old-tag-2', 'GET', 200, 1, datetime('now', '-3 days')),
    (datetime('now'), datetime('now'), '127.0.0.1', 'old-session-3', 'old-repo-3', 'secret', 'old-tag-3', 'GET', 200, 1, datetime('now', '-3 days'));

-- 插入新数据（当前时间，每条记录间隔1分钟）
INSERT INTO attestation_records (created_at, updated_at, client_ip, session_id, request_body, claims, status, successful, timestamp, source_service)
VALUES 
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-1', 'new-request-1', 'new-claims-1', 200, 1, datetime('now', '-6 minutes'), 'kbs'),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-2', 'new-request-2', 'new-claims-2', 200, 1, datetime('now', '-5 minutes'), 'kbs'),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-3', 'new-request-3', 'new-claims-3', 200, 1, datetime('now', '-4 minutes'), 'kbs'),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-4', 'new-request-4', 'new-claims-4', 200, 1, datetime('now', '-3 minutes'), 'kbs'),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-5', 'new-request-5', 'new-claims-5', 200, 1, datetime('now', '-2 minutes'), 'kbs'),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-6', 'new-request-6', 'new-claims-6', 200, 1, datetime('now', '-1 minutes'), 'kbs'),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-7', 'new-request-7', 'new-claims-7', 200, 1, datetime('now'), 'kbs');

INSERT INTO resource_requests (created_at, updated_at, client_ip, session_id, repository, type, tag, method, status, successful, timestamp)
VALUES 
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-1', 'new-repo-1', 'secret', 'new-tag-1', 'GET', 200, 1, datetime('now', '-6 minutes')),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-2', 'new-repo-2', 'secret', 'new-tag-2', 'GET', 200, 1, datetime('now', '-5 minutes')),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-3', 'new-repo-3', 'secret', 'new-tag-3', 'GET', 200, 1, datetime('now', '-4 minutes')),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-4', 'new-repo-4', 'secret', 'new-tag-4', 'GET', 200, 1, datetime('now', '-3 minutes')),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-5', 'new-repo-5', 'secret', 'new-tag-5', 'GET', 200, 1, datetime('now', '-2 minutes')),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-6', 'new-repo-6', 'secret', 'new-tag-6', 'GET', 200, 1, datetime('now', '-1 minutes')),
    (datetime('now'), datetime('now'), '127.0.0.1', 'new-session-7', 'new-repo-7', 'secret', 'new-tag-7', 'GET', 200, 1, datetime('now'));
EOF

    log_info "测试数据生成完成"
}

# 检查数据库记录数量
check_record_count() {
    local description="$1"
    log_info "$description"
    
    local attestation_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM attestation_records WHERE deleted_at IS NULL;")
    local resource_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM resource_requests WHERE deleted_at IS NULL;")
    
    echo "  - 认证记录数量: $attestation_count"
    echo "  - 资源请求记录数量: $resource_count"
    
    return 0
}

# 打印所有数据库条目
print_all_db_entries() {
    local description="$1"
    log_info "$description"
    
    echo "=== 认证记录 (attestation_records) ==="
    sqlite3 -header -column "$DB_FILE" "SELECT id, session_id, client_ip, status, successful, timestamp, source_service FROM attestation_records WHERE deleted_at IS NULL ORDER BY timestamp;"
    
    echo ""
    echo "=== 资源请求记录 (resource_requests) ==="
    sqlite3 -header -column "$DB_FILE" "SELECT id, session_id, client_ip, repository, type, tag, method, status, successful, timestamp FROM resource_requests WHERE deleted_at IS NULL ORDER BY timestamp;"
    
    echo ""
    echo "=== 已删除的认证记录 (deleted attestation_records) ==="
    sqlite3 -header -column "$DB_FILE" "SELECT id, session_id, client_ip, status, successful, timestamp, source_service, deleted_at FROM attestation_records WHERE deleted_at IS NOT NULL ORDER BY timestamp;"
    
    echo ""
    echo "=== 已删除的资源请求记录 (deleted resource_requests) ==="
    sqlite3 -header -column "$DB_FILE" "SELECT id, session_id, client_ip, repository, type, tag, method, status, successful, timestamp, deleted_at FROM resource_requests WHERE deleted_at IS NOT NULL ORDER BY timestamp;"
    
    echo "=================================================="
    echo ""
}

# 等待清理执行
wait_for_cleanup() {
    log_info "等待审计清理执行..."
    
    # 等待清理间隔时间（1小时 + 一些缓冲时间）
    # 在测试环境中，我们可以通过检查日志来确认清理是否执行
    local max_wait=120  # 最多等待2分钟
    local waited=0
    
    while [ $waited -lt $max_wait ]; do
        if grep -q "Audit cleanup completed" "$LOG_FILE" 2>/dev/null; then
            log_info "检测到清理操作完成"
            return 0
        fi
        
        if grep -q "Starting audit records cleanup" "$LOG_FILE" 2>/dev/null; then
            log_info "检测到清理操作开始"
        fi
        
        sleep 5
        waited=$((waited + 5))
        echo -n "."
    done
    
    echo ""
    log_warn "未在预期时间内检测到清理操作，继续测试..."
    return 0
}

# 验证清理结果
verify_cleanup_results() {
    log_info "验证清理结果..."
    
    local attestation_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM attestation_records WHERE deleted_at IS NULL;")
    local resource_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM resource_requests WHERE deleted_at IS NULL;")
    
    # 根据配置，应该保留最多5条记录，且旧记录应该被删除
    if [ $attestation_count -le 5 ] && [ $resource_count -le 5 ]; then
        log_info "✓ 记录数量符合max_records限制"
    else
        log_error "✗ 记录数量超过max_records限制"
        return 1
    fi
    
    # 检查是否还有旧记录（3天前的）
    local old_attestation_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM attestation_records WHERE deleted_at IS NULL AND timestamp < datetime('now', '-2 days');")
    local old_resource_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM resource_requests WHERE deleted_at IS NULL AND timestamp < datetime('now', '-2 days');")
    
    if [ $old_attestation_count -eq 0 ] && [ $old_resource_count -eq 0 ]; then
        log_info "✓ 旧记录已被正确清理"
    else
        log_error "✗ 仍有旧记录未被清理"
        return 1
    fi
    
    return 0
}

# 显示日志摘要
show_log_summary() {
    log_info "显示相关日志摘要..."
    
    if [ -f "$LOG_FILE" ]; then
        echo "=== 审计清理相关日志 ==="
        grep -i "audit\|cleanup" "$LOG_FILE" | tail -20
        echo "========================="
    fi
}

# 主测试流程
main() {
    log_info "开始审计清理功能集成测试"
    
    # 1. 创建测试配置
    create_test_config
    
    # 2. 生成测试数据
    generate_test_data
    
    # 3. 检查初始数据
    check_record_count "初始数据状态:"
    print_all_db_entries "初始数据库条目详情:"
    
    # 4. 启动gateway服务
    if ! start_gateway; then
        log_error "无法启动gateway服务，测试失败"
        return 1
    fi
    
    # 5. 等待清理执行
    wait_for_cleanup
    
    # 6. 检查清理后的数据
    check_record_count "清理后数据状态:"
    print_all_db_entries "清理后数据库条目详情:"
    
    # 7. 验证清理结果
    if verify_cleanup_results; then
        log_info "✓ 审计清理功能测试通过"
    else
        log_error "✗ 审计清理功能测试失败"
        show_log_summary
        return 1
    fi
    
    # 8. 显示日志摘要
    show_log_summary
    
    log_info "集成测试完成"
    return 0
}

# 检查依赖
check_dependencies() {
    if ! command -v sqlite3 &> /dev/null; then
        log_error "sqlite3 命令未找到，请安装sqlite3"
        return 1
    fi
    
    if ! command -v curl &> /dev/null; then
        log_error "curl 命令未找到，请安装curl"
        return 1
    fi
    
    if [ ! -f "../gateway" ]; then
        log_error "gateway可执行文件未找到，请先编译项目"
        return 1
    fi
    
    return 0
}

# 显示使用说明
show_usage() {
    echo "审计清理功能集成测试脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help     显示此帮助信息"
    echo "  -v, --verbose  详细输出模式"
    echo ""
    echo "此脚本将:"
    echo "1. 创建测试配置文件"
    echo "2. 生成测试审计数据"
    echo "3. 启动gateway服务"
    echo "4. 等待审计清理执行"
    echo "5. 验证清理结果"
    echo ""
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -v|--verbose)
            set -x
            shift
            ;;
        *)
            log_error "未知选项: $1"
            show_usage
            exit 1
            ;;
    esac
done

# 执行测试
if check_dependencies; then
    main
    exit $?
else
    exit 1
fi 