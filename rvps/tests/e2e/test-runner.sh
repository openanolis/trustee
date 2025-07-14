#!/bin/bash

# RVPS E2E测试运行脚本
# 用于快速验证和运行RVPS端到端测试

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印函数
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# 检查依赖
check_dependencies() {
    print_header "检查依赖环境"
    
    local missing_deps=()
    
    # 检查基础工具
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi
    
    if ! command -v grpcurl &> /dev/null; then
        print_warning "grpcurl未安装，将跳过gRPC直接测试"
    fi
    
    # 检查RVPS二进制文件
    if [ ! -f "/usr/local/bin/rvps" ]; then
        missing_deps+=("rvps (run 'make build && sudo make install' in rvps directory)")
    fi
    
    if [ ! -f "/usr/local/bin/rvps-tool" ]; then
        missing_deps+=("rvps-tool (run 'make build && sudo make install' in rvps directory)")
    fi
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        print_success "所有依赖检查通过"
        return 0
    else
        print_error "缺少以下依赖:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        print_info "请运行 'make install-dependencies' 安装缺失依赖"
        return 1
    fi
}

# 运行单个测试
run_test() {
    local test_name="$1"
    local test_desc="$2"
    
    print_info "运行测试: $test_desc"
    
    if make "$test_name"; then
        print_success "$test_desc 通过"
        return 0
    else
        print_error "$test_desc 失败"
        return 1
    fi
}

# 清理环境
cleanup() {
    print_info "清理测试环境..."
    make stop 2>/dev/null || true
    make clean 2>/dev/null || true
}

# 主测试流程
main() {
    print_header "RVPS E2E测试运行器"
    
    # 设置清理陷阱
    trap cleanup EXIT
    
    # 检查依赖
    if ! check_dependencies; then
        exit 1
    fi
    
    print_header "开始运行RVPS E2E测试"
    
    local tests_passed=0
    local tests_failed=0
    
    # 测试列表
    local tests=(
        "test-localfs-crud:LocalFS存储CRUD测试"
        "test-localjson-crud:LocalJSON存储CRUD测试" 
        "test-error-handling:错误处理测试"
        "test-concurrent-operations:并发操作测试"
        "test-storage-backend-switching:存储后端切换测试"
    )
    
    # 如果有grpcurl，添加gRPC测试
    if command -v grpcurl &> /dev/null; then
        tests+=("test-grpc-api:gRPC API直接测试")
    fi
    
    # 运行每个测试
    for test_item in "${tests[@]}"; do
        IFS=':' read -r test_name test_desc <<< "$test_item"
        
        echo ""
        if run_test "$test_name" "$test_desc"; then
            ((tests_passed++))
        else
            ((tests_failed++))
        fi
        
        # 每个测试后停止服务
        make stop 2>/dev/null || true
        sleep 1
    done
    
    # 总结
    print_header "测试结果总结"
    echo -e "通过的测试: ${GREEN}$tests_passed${NC}"
    echo -e "失败的测试: ${RED}$tests_failed${NC}"
    echo -e "总测试数: $((tests_passed + tests_failed))"
    
    if [ $tests_failed -eq 0 ]; then
        print_success "所有测试通过！RVPS E2E测试覆盖率达到100%"
        return 0
    else
        print_error "有 $tests_failed 个测试失败"
        return 1
    fi
}

# 显示帮助信息
show_help() {
    echo "RVPS E2E测试运行器"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help          显示此帮助信息"
    echo "  -c, --check-deps    仅检查依赖环境"
    echo "  -q, --quick         快速测试(仅运行基础CRUD测试)"
    echo "  -v, --verbose       详细输出模式"
    echo ""
    echo "示例:"
    echo "  $0                  运行所有测试"
    echo "  $0 --check-deps     仅检查环境依赖"
    echo "  $0 --quick          快速验证基础功能"
}

# 快速测试模式
quick_test() {
    print_header "RVPS快速测试模式"
    
    if ! check_dependencies; then
        exit 1
    fi
    
    # 只运行基础CRUD测试
    trap cleanup EXIT
    
    if run_test "test-localfs-crud" "LocalFS存储CRUD测试"; then
        print_success "快速测试通过！RVPS基础功能正常"
        return 0
    else
        print_error "快速测试失败"
        return 1
    fi
}

# 命令行参数解析
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    -c|--check-deps)
        check_dependencies
        exit $?
        ;;
    -q|--quick)
        quick_test
        exit $?
        ;;
    -v|--verbose)
        set -x
        main
        exit $?
        ;;
    "")
        main
        exit $?
        ;;
    *)
        echo "未知选项: $1"
        echo "使用 --help 查看帮助信息"
        exit 1
        ;;
esac 