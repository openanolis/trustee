# Makefile for trustee installation
# 用法: make install [BUILDROOT=path] [PREFIX=path] [CONFIG_DIR=path]

# 设置默认值
BUILDROOT ?=
PREFIX ?= /usr
CONFIG_DIR ?= /etc/trustee

# 获取版本号
VERSION ?= $(shell grep "^Version:" ../rpm/AnolisOS23/rpmbuild-layout/SPECS/trustee.spec | awk '{print $$2}')

# 设置默认目标
.DEFAULT_GOAL := build

# 显示帮助信息
help:
	@echo "用法:"
	@echo "  make          # 默认执行编译"
	@echo "  make build    # 编译所有组件"
	@echo "  make build-frontend # 编译前端组件"
	@echo "  make install [BUILDROOT=path] [PREFIX=path] [CONFIG_DIR=path]"
	@echo "  make install-frontend [BUILDROOT=path] [PREFIX=path] [CONFIG_DIR=path]"
	@echo "  make create-build-artifacts  # 创建RPM打包所需的构建产物"
	@echo ""
	@echo "参数说明:"
	@echo "  BUILDROOT: 构建根目录 (默认为空)"
	@echo "  PREFIX: 安装前缀 (默认: /usr)"
	@echo "  CONFIG_DIR: 配置文件目录 (默认: /etc/trustee)"
	@echo ""
	@echo "示例:"
	@echo "  make install"
	@echo "  make install BUILDROOT=/tmp/build PREFIX=/usr/local"
	@echo "  make install CONFIG_DIR=/opt/trustee/config"
	@echo "  make install-frontend  # 安装前端组件"
	@echo "  make create-build-artifacts  # 创建RPM构建产物"

# 编译目标
build:
	cd ..
	@echo "开始编译 trustee 组件..."
	cd ../trustee-gateway && \
	CGO_ENABLED=1 GOOS=linux go build -mod vendor -a -installsuffix cgo -ldflags="-s -w" -o gateway cmd/server/main.go && \
	cd ..
	cargo build -p kbs --locked --release --no-default-features --features coco-as-grpc,aliyun,tpm-pca
	cargo build --bin restful-as --release --features restful-bin --locked
	cargo build --bin grpc-as --release --features grpc-bin --locked
	cargo build --bin rvps --release
	cargo build --bin rvps-tool --release
	@echo "编译 trustee-gateway..."
	@echo "编译完成"

# 编译前端目标
build-frontend:
	@echo "开始编译前端..."
	cd ../frontend && \
	npm ci --production=false && \
	npm run build
	@echo "前端编译完成"

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
	install -m 644 system/trustee-gateway.service $(BUILDROOT)$(PREFIX)/lib/systemd/system/trustee-gateway.service
	
	# 创建配置目录并安装配置文件
	install -d -p $(BUILDROOT)$(CONFIG_DIR)
	install -m 644 configs/kbs-config.toml $(BUILDROOT)$(CONFIG_DIR)/kbs-config.toml
	install -m 644 configs/as-config.json $(BUILDROOT)$(CONFIG_DIR)/as-config.json
	install -m 644 configs/rvps.json $(BUILDROOT)$(CONFIG_DIR)/rvps.json
	install -m 644 configs/gateway.yml $(BUILDROOT)$(CONFIG_DIR)/gateway.yml
	
	# 创建 bin 目录并安装可执行文件
	install -d -p $(BUILDROOT)$(PREFIX)/bin
	install -m 755 ../target/release/kbs $(BUILDROOT)$(PREFIX)/bin/kbs
	install -m 755 ../target/release/restful-as $(BUILDROOT)$(PREFIX)/bin/restful-as
	install -m 755 ../target/release/grpc-as $(BUILDROOT)$(PREFIX)/bin/grpc-as
	install -m 755 ../target/release/rvps $(BUILDROOT)$(PREFIX)/bin/rvps
	install -m 755 ../target/release/rvps-tool $(BUILDROOT)$(PREFIX)/bin/rvps-tool
	install -m 755 ../trustee-gateway/gateway $(BUILDROOT)$(PREFIX)/bin/trustee-gateway
	
	install -d -p $(BUILDROOT)$(PREFIX)/include
	install -d -p $(BUILDROOT)$(PREFIX)/lib64
	cp intel-deps/include/sgx_* $(BUILDROOT)$(PREFIX)/include/
	cp intel-deps/lib64/lib* $(BUILDROOT)$(PREFIX)/lib64/
	cp intel-deps/etc/sgx_* $(BUILDROOT)/etc/

# 安装前端目标
install-frontend:
	@echo "安装前端配置:"
	@echo "  BUILDROOT: $(if $(BUILDROOT),$(BUILDROOT),'(空)')"
	@echo "  PREFIX: $(PREFIX)"
	@echo "  CONFIG_DIR: $(CONFIG_DIR)"
	@echo ""
	
	# 安装前端静态文件
	install -d -p $(BUILDROOT)/usr/share/nginx/html/trustee
	cp -r ../frontend/dist/* $(BUILDROOT)/usr/share/nginx/html/trustee/
	
	# 安装 nginx 配置文件
	install -d -p $(BUILDROOT)/etc/nginx/conf.d
	install -m 644 ../frontend/nginx.conf $(BUILDROOT)/etc/nginx/conf.d/trustee-frontend.conf
	
	# 安装前端 systemd 服务文件
	install -d -p $(BUILDROOT)$(PREFIX)/lib/systemd/system
	install -m 644 system/trustee-frontend.service $(BUILDROOT)$(PREFIX)/lib/systemd/system/trustee-frontend.service
	
	# 安装前端启动脚本
	install -d -p $(BUILDROOT)$(PREFIX)/bin
	install -m 755 ../frontend/trustee-frontend-start.sh $(BUILDROOT)$(PREFIX)/bin/trustee-frontend-start
	
	@echo "前端安装完成"

# Create build artifacts for RPM packaging
create-build-artifacts:
	@echo "Creating build artifacts for RPM packaging..."
	@echo "  Version: $(VERSION)"

	# Create SOURCES directory
	@echo "  Creating SOURCES directory..."
	mkdir -p ../rpm/AnolisOS23/rpmbuild-layout/SOURCES

	# Create Source0: Main source tarball
	@echo "  Creating main source tarball..."
	mkdir -p /tmp/trustee-$(VERSION) && cp -r ../* /tmp/trustee-$(VERSION)/ && \
	(cd /tmp && tar --exclude='trustee-$(VERSION)/target' --exclude='trustee-$(VERSION)/.git' \
	--exclude='trustee-$(VERSION)/dist/vendor.tar.gz' --exclude='trustee-$(VERSION)/dist/go-vendor.tar.gz' \
	--exclude='trustee-$(VERSION)/dist/frontend_node_modules.tar.gz' --exclude='trustee-$(VERSION)/frontend/node_modules' \
	--exclude='trustee-$(VERSION)/trustee-gateway/vendor' --exclude='trustee-$(VERSION)/.gitignore' \
	--exclude='trustee-$(VERSION)/*.tar.gz' -czf /tmp/trustee-$(VERSION).tar.gz trustee-$(VERSION)) && \
	mv /tmp/trustee-$(VERSION).tar.gz ../rpm/AnolisOS23/rpmbuild-layout/SOURCES/ && rm -rf /tmp/trustee-$(VERSION)
	
	# Create Source1: Rust vendor tarball and Source2: Cargo config.toml
	@echo "  Creating Rust vendor tarball and Cargo config.toml..."
	cd .. && \
    cargo vendor --locked vendor > rpm/AnolisOS23/rpmbuild-layout/SOURCES/config.toml && \
    printf '\n[net]\ngit-fetch-with-cli = true\n' >> rpm/AnolisOS23/rpmbuild-layout/SOURCES/config.toml && \
    tar -czf rpm/AnolisOS23/rpmbuild-layout/SOURCES/vendor.tar.gz vendor
	
	# Create Source3: Go vendor tarball for trustee-gateway
	@echo "  Creating Go vendor tarball..."
	cd ../trustee-gateway && go mod vendor && cd .. && tar -czf rpm/AnolisOS23/rpmbuild-layout/SOURCES/go-vendor.tar.gz -C trustee-gateway vendor
	
	# Create Source4: Frontend node_modules tarball
	@echo "  Creating frontend node_modules tarball..."
	cd ../frontend && npm ci --production=false && cd .. && tar -czf rpm/AnolisOS23/rpmbuild-layout/SOURCES/frontend_node_modules.tar.gz -C frontend node_modules
	
	@echo "Build artifacts created successfully:"
	@echo "  - trustee-$(VERSION).tar.gz (Source0)"
	@echo "  - vendor.tar.gz (Source1)"
	@echo "  - config.toml (Source2)"
	@echo "  - go-vendor.tar.gz (Source3)"
	@echo "  - frontend_node_modules.tar.gz (Source4)"

# Clean build artifacts
clean-build-artifacts:
	@echo "Cleaning build artifacts..."
	rm -f ../rpm/AnolisOS23/rpmbuild-layout/SOURCES/trustee-$(VERSION).tar.gz
	rm -f ../rpm/AnolisOS23/rpmbuild-layout/SOURCES/vendor.tar.gz
	rm -f ../rpm/AnolisOS23/rpmbuild-layout/SOURCES/go-vendor.tar.gz
	rm -f ../rpm/AnolisOS23/rpmbuild-layout/SOURCES/frontend_node_modules.tar.gz
	rm -rf ../vendor/
	rm -rf ../trustee-gateway/vendor/
	@echo "Build artifacts cleaned successfully."
	
.PHONY: help install build build-frontend install-frontend create-build-artifacts
