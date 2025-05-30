# Makefile for trustee installation
# 用法: make install [BUILDROOT=path] [PREFIX=path] [CONFIG_DIR=path]

# 设置默认值
BUILDROOT ?=
PREFIX ?= /usr
CONFIG_DIR ?= /etc/trustee

# 显示帮助信息
help:
	@echo "用法: make install [BUILDROOT=path] [PREFIX=path] [CONFIG_DIR=path]"
	@echo "  BUILDROOT: 构建根目录 (默认为空)"
	@echo "  PREFIX: 安装前缀 (默认: /usr)"
	@echo "  CONFIG_DIR: 配置文件目录 (默认: /etc/trustee)"
	@echo ""
	@echo "示例:"
	@echo "  make install"
	@echo "  make install BUILDROOT=/tmp/build PREFIX=/usr/local"
	@echo "  make install CONFIG_DIR=/opt/trustee/config"

# 安装目标
install:
	@echo "安装配置:"
	@echo "  BUILDROOT: $(if $(BUILDROOT),$(BUILDROOT),'(空)')"
	@echo "  PREFIX: $(PREFIX)"
	@echo "  CONFIG_DIR: $(CONFIG_DIR)"
	@echo ""
	
	# 创建 systemd 服务目录并安装服务文件
	install -d -p $(BUILDROOT)$(PREFIX)/lib/systemd/system
	install -m 644 system/kbs.service $(BUILDROOT)$(PREFIX)/lib/systemd/system/kbs.service
	install -m 644 system/as.service $(BUILDROOT)$(PREFIX)/lib/systemd/system/as.service
	install -m 644 system/rvps.service $(BUILDROOT)$(PREFIX)/lib/systemd/system/rvps.service
	install -m 644 system/as-restful.service $(BUILDROOT)$(PREFIX)/lib/systemd/system/as-restful.service
	install -m 644 system/trustee.service $(BUILDROOT)$(PREFIX)/lib/systemd/system/trustee.service
	
	# 创建配置目录并安装配置文件
	install -d -p $(BUILDROOT)$(CONFIG_DIR)
	install -m 644 configs/kbs-config.toml $(BUILDROOT)$(CONFIG_DIR)/kbs-config.toml
	install -m 644 configs/as-config.json $(BUILDROOT)$(CONFIG_DIR)/as-config.json
	install -m 644 configs/rvps.json $(BUILDROOT)$(CONFIG_DIR)/rvps.json
	
	# 创建 bin 目录并安装可执行文件
	install -d -p $(BUILDROOT)$(PREFIX)/bin
	install -m 755 ../target/release/kbs $(BUILDROOT)$(PREFIX)/bin/kbs
	install -m 755 ../target/release/restful-as $(BUILDROOT)$(PREFIX)/bin/restful-as
	install -m 755 ../target/release/grpc-as $(BUILDROOT)$(PREFIX)/bin/grpc-as
	install -m 755 ../target/release/rvps $(BUILDROOT)$(PREFIX)/bin/rvps
	install -m 755 ../target/release/kbs-client $(BUILDROOT)$(PREFIX)/bin/kbs-client
	install -m 755 ../target/release/rvps-tool $(BUILDROOT)$(PREFIX)/bin/rvps-tool
	
	# 创建 include 和 lib64 目录并安装 Intel 依赖
	install -d -p $(BUILDROOT)$(PREFIX)/include
	install -d -p $(BUILDROOT)$(PREFIX)/lib64
	cp intel-deps/include/sgx_* $(BUILDROOT)$(PREFIX)/include/
	cp intel-deps/lib64/lib* $(BUILDROOT)$(PREFIX)/lib64/
	cp intel-deps/etc/sgx_* $(BUILDROOT)/etc/

.PHONY: help install 