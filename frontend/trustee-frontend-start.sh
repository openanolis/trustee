#!/bin/bash
# Trustee Frontend 启动脚本

# 检查配置文件
if [ ! -f /etc/nginx/conf.d/trustee-frontend.conf ]; then
    echo "错误: nginx 配置文件不存在"
    exit 1
fi

# 测试 nginx 配置
nginx -t -c /etc/nginx/nginx.conf
if [ $? -ne 0 ]; then
    echo "错误: nginx 配置文件有误"
    exit 1
fi

# 确保 trustee-gateway 正在运行
if ! systemctl is-active --quiet trustee-gateway; then
    echo "警告: trustee-gateway 服务未运行，尝试启动..."
    systemctl start trustee-gateway
fi

# 启动 nginx
systemctl start nginx
systemctl enable nginx

echo "Trustee Frontend 已启动，访问地址: http://localhost:8082" 