# TDX ECS 验收

在单独创建的验收 TDVM 内运行。本套件使用真实 nginx、Gateway、AS、RVPS、KBS、浏览器和原生 TDX 客户端。完整模式要求阿里云返回的 ECS ID 与 Trustee 管理页中的活跃 AA 心跳一致。

## 准备

1. 按[部署说明](../README.md)准备专用验收上下文。给 `prepare.sh` 传入 `--external-attestation` 并将管理员公钥参数设为 `-`。目标为 `tdx-interop`。实例首次启动时在 `/var/lib/trustee-shelter/identity/admin.key` 生成临时管理私钥。该模式由客户端和 AS 完成取密时的证明。Shelter 的服务端启动证明是另一项检查。
2. 准备支持 Intel TDX 的 `trustee-attester`。它来自 [openanolis/guest-components v1.8.0](https://github.com/openanolis/guest-components/tree/v1.8.0/attestation-agent/kbs_protocol)，不在 Trustee 服务端 RPM 中。在与来宾 ABI 兼容、已安装 Rust 1.88 和 Intel DCAP TDX 开发库的 x86_64 构建机上执行以下命令，仅将生成的可执行文件及其缺少的运行库放入来宾。运行 `ldd` 确认依赖齐全。

   ```sh
   git clone --branch v1.8.0 --depth 1 https://github.com/openanolis/guest-components.git
   cd guest-components
   cargo build --release --locked -p kbs_protocol --bin trustee-attester \
     --no-default-features --features bin,background_check,rust-crypto,tdx-attester
   ldd target/release/trustee-attester
   ```

3. 私网验收可通过云助手运行机内命令。下载官方 Linux RPM，把以下文件放入**专用验收上下文**，再构建并启动。云助手使获授权的 ECS 运维身份能在来宾中执行命令。该软件包只加入验收镜像。[阿里云安装说明](https://help.aliyun.com/zh/ecs/user-guide/install-the-cloud-assistant-agent)

   ```sh
   # TDX_CLIENT 指向上一步的可执行文件
   test -f "$ctx/guest/interop-local-admin" || exit 1
   ASSIST_RPM=$(mktemp)
   curl -fL https://aliyun-client-assist-cn-beijing.oss-cn-beijing.aliyuncs.com/linux/aliyun_assist_2.2.4.1097.rpm -o "$ASSIST_RPM" || exit 1
   echo "174a9cd433f366fba8172d79610b77b13d41e643770d86e4a165815bf831bcd4  $ASSIST_RPM" | sha256sum -c - || exit 1
   install -m 0644 "$ASSIST_RPM" "$ctx/guest/rpms/aliyun_assist.rpm"
   install -m 0755 "$TDX_CLIENT" "$ctx/guest/trustee-attester"
   shelter build -t trustee-e2e "$ctx"
   shelter run -d --target tdx-interop --name trustee-e2e-01 trustee-e2e
   ```

4. 在部署输出中记下 ECS 实例 ID。通过云助手将 `shelter/tests/` 和 `shelter/guest/policy.rego` 送入来宾，保留目录结构。在来宾内安装 Python 3.9+、`certutil`（ALinux 软件包 `nss-tools`）、Chromium 及其运行库。配方根文件系统为 8 GiB，Rust 编译和浏览器缓存可使用单独的临时盘。以下命令中的 `/mnt/test` 是已挂载且可执行的测试盘。在出网受限的实例上可预先准备对应架构的 wheel、浏览器及运行库。

   ```sh
   python3.11 -m venv /mnt/test/venv
   /mnt/test/venv/bin/pip install 'playwright==1.56.0'
   export PLAYWRIGHT_BROWSERS_PATH=/mnt/test/browsers
   /mnt/test/venv/bin/python -m playwright install --only-shell chromium
   ```

## 执行

用有权读取实例本地测试私钥的账号，在来宾内的 Trustee 源码目录运行。测试需要 `shelter/tests` 和相邻的 `shelter/guest/policy.rego`。有系统 Chromium 时可以加 `--chromium /path/to/chromium`。

```sh
export PATH="/usr/share/trustee-shelter:$PATH"
/mnt/test/venv/bin/python shelter/tests/acceptance.py \
  --admin-key /var/lib/trustee-shelter/identity/admin.key \
  --instance-id "$ECS_INSTANCE_ID"
```

浏览器默认连接 `https://127.0.0.1:8082`，也支持 `--origin https://trustee.internal:8082`。脚本将该域名解析到回环地址，用实例 CA 建立临时 Chromium 信任库并校验证书。管理员私钥由页面在此浏览器中签名，管理员 JWT 只发往回环服务。原生客户端另建 RCAR 会话，使用同一个 CA 验证服务器。测试结束时清理浏览器配置。

默认 TDX 客户端是同一来宾内的独立进程。要验证跨机的网络访问、证书有效期和远程取密，可按下节使用两台 ECS。

## 两台 ECS 通过私网验收

1. **服务端**按上文部署专用 Trustee 验收实例。保留其 ID、私网 IPv4、管理私钥的来宾路径，以及已安装 Playwright 的 Python、Chromium 和 `shelter/tests` 的绝对路径。
2. **客户端**另选一台 TDX ECS，把同版本的 `shelter/tests/tdx-client.sh` 和原生 `trustee-attester` 装入来宾并赋予执行权限。两机位于同地域且 VPC 可互通，服务端的安全组和 nginx 客户端白名单允许该客户端私网地址访问 TCP 8082。确认两机的 UTC 时间已同步，服务端 nginx 正常写入 combined 格式的访问日志。
3. **部署机**需要 Python 3.8+、OpenSSL 1.1.1+ 和已认证的 `aliyun` CLI，能读取服务端串口，在两台实例上调用云助手 `RunCommand`、`DescribeInvocationResults`。两机的云助手应以 root 执行验收（需要读取服务端的机内验收密钥、在客户端创建临时挂载命名空间）。在部署机设置以下变量并运行：

   ```sh
   # REGION、SERVER_ID、SERVER_PRIVATE_IP、CLIENT_ID 填本次的部署输出。
   # 下列是来宾内的示例安装路径，可替换成自己的。
   SERVER_TESTS=/opt/trustee/shelter/tests
   CLIENT_TESTS=/opt/trustee/shelter/tests
   SERVER_PYTHON=/mnt/test/venv/bin/python
   SERVER_CHROMIUM=/usr/bin/chromium-browser
   CLIENT_ATTESTER=/usr/local/bin/trustee-attester

   python3 shelter/fetch-ca.py "$REGION" "$SERVER_ID" > trustee-ca.pem &&
   python3 shelter/tests/two-ecs.py \
     --region "$REGION" --server "$SERVER_ID" --server-ip "$SERVER_PRIVATE_IP" \
     --client "$CLIENT_ID" --ca trustee-ca.pem \
     --server-tests "$SERVER_TESTS" --client-tests "$CLIENT_TESTS" \
     --server-python "$SERVER_PYTHON" --chromium "$SERVER_CHROMIUM" \
     --client-attester "$CLIENT_ATTESTER"
   ```

浏览器和管理员私钥都在服务端。独立客户端收到该实例的公开 CA，把 `trustee.internal` 临时解析至服务端私网地址，通过 HTTPS 直接连接。部署机只转交随机资源路径、拒绝状态和成功时的 SHA-256。完整通过要求同一资源先收到 403、再收到 200，服务端的两条 GET 各关联一次成功 TDX 证明；浏览器核对解密摘要，nginx 入口日志还需确认两次请求均来自该客户端的私网 IP。服务端密钥、CA 或日志路径有变时可分别传 `--admin-key`、`--server-ca`、`--access-log`。

## 判定

| 检查 | 通过条件 |
| --- | --- |
| 服务与前端 | systemd 服务组和六个组件均 active，浏览器登录，健康页的四项服务均正常 |
| 策略和参考值 | 新建、回读、修改、删除独立 AS 策略，保存并回读 KBS 资源策略，对同一 RVPS 参考值先后登记两个摘要、逐次查询并删除测试项 |
| 取密与审计 | 同一个随机资源先经真实证明后收到 403；安装只授权该资源的临时策略后重新证明，返回 200；解密后 SHA-256 与上传的 48 字节随机资源完全一致，两次 GET 分别关联本次成功的 TDX 证明 |
| 资源、实例和退出 | 页面查询、文本/二进制上传及删除；找到指定 ECS 的活跃心跳，搜索、重置、刷新；退出后清除会话 |

临时策略要求 AS 签名的 EAR 中有受认可的 Intel TDX 硬件和关闭 DEBUG 的 TD，且路径与本次随机测试资源完全匹配。该输入验证平台取密互操作性，生产负载应另外配置经批准的启动度量和参考值。测试仅接受配方出厂的拒绝策略；取密结束后恢复原策略并删除测试资源。如测试进程被强杀或实例断电，请检查管理页中的资源策略，必要时恢复 `shelter/guest/policy.rego` 并删掉本轮测试对象。

在无 TDX 的本地环境，可运行 `--management-only` 验证真实管理页面与后端。该模式单独报告结果，跳过 systemd、TDX 证明、解密及其关联审计；不计入完整验收。
