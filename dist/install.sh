#!/bin/bash

# 设置默认值
BUILDROOT=""
PREFIX="/usr"
CONFIG_DIR="/etc/trustee"

# 解析命令行参数
for arg in "$@"; do
    case $arg in
        ROOTDIR=*)
            BUILDROOT="${arg#*=}"
            shift
            ;;
        PREFIX=*)
            PREFIX="${arg#*=}"
            shift
            ;;
        CONFIG_DIR=*)
            CONFIG_DIR="${arg#*=}"
            shift
            ;;
        --help|-h)
            echo "用法: $0 [ROOTDIR=path] [PREFIX=path] [CONFIG_DIR=path]"
            echo "  ROOTDIR: 构建根目录 (默认为空)"
            echo "  PREFIX: 安装前缀 (默认: /usr)"
            echo "  CONFIG_DIR: 配置文件目录 (默认: /etc/trustee)"
            exit 0
            ;;
        *)
            echo "未知参数: $arg"
            echo "使用 --help 查看帮助"
            exit 1
            ;;
    esac
done

# 打印配置信息
echo "安装配置:"
echo "  BUILDROOT: ${BUILDROOT:-'(空)'}"
echo "  PREFIX: $PREFIX"
echo "  CONFIG_DIR: $CONFIG_DIR"
echo

install -d -p ${BUILDROOT}${PREFIX}/lib/systemd/system
install -m 644 system/kbs.service ${BUILDROOT}${PREFIX}/lib/systemd/system/kbs.service
install -m 644 system/as.service ${BUILDROOT}${PREFIX}/lib/systemd/system/as.service
install -m 644 system/rvps.service ${BUILDROOT}${PREFIX}/lib/systemd/system/rvps.service
install -m 644 system/as-restful.service ${BUILDROOT}${PREFIX}/lib/systemd/system/as-restful.service
install -m 644 system/trustee.service ${BUILDROOT}${PREFIX}/lib/systemd/system/trustee.service
install -m 644 system/iam.service ${BUILDROOT}${PREFIX}/lib/systemd/system/iam.service
install -d -p ${BUILDROOT}/etc/trustee
install -m 644 configs/kbs-config.toml ${BUILDROOT}${CONFIG_DIR}/kbs-config.toml
install -m 644 configs/as-config.json ${BUILDROOT}${CONFIG_DIR}/as-config.json
install -m 644 configs/rvps.json ${BUILDROOT}${CONFIG_DIR}/rvps.json
install -m 644 configs/iam.toml ${BUILDROOT}${CONFIG_DIR}/iam.toml
install -d -p ${BUILDROOT}${PREFIX}/bin
install -m 755 ../target/release/kbs ${BUILDROOT}${PREFIX}/bin/kbs
install -m 755 ../target/release/restful-as ${BUILDROOT}${PREFIX}/bin/restful-as
install -m 755 ../target/release/grpc-as ${BUILDROOT}${PREFIX}/bin/grpc-as
install -m 755 ../target/release/rvps ${BUILDROOT}${PREFIX}/bin/rvps
install -m 755 ../target/release/kbs-client ${BUILDROOT}${PREFIX}/bin/kbs-client
install -m 755 ../target/release/rvps-tool ${BUILDROOT}${PREFIX}/bin/rvps-tool
install -m 755 ../target/release/iam ${BUILDROOT}${PREFIX}/bin/iam
install -d -p ${BUILDROOT}${PREFIX}/include
install -d -p ${BUILDROOT}${PREFIX}/lib64
cp intel-deps/include/sgx_* ${BUILDROOT}${PREFIX}/include/
cp intel-deps/lib64/lib* ${BUILDROOT}${PREFIX}/lib64/
cp intel-deps/etc/sgx_* ${BUILDROOT}/etc/
