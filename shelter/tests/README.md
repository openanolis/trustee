# TDX ECS 验收

在单独创建的验收 TDVM 内运行。本套件使用真实 nginx、Gateway、AS、RVPS、KBS、浏览器和原生 TDX 客户端。完整模式要求阿里云返回的 ECS ID 与 Trustee 管理页中的活跃 AA 心跳一致。

## 准备

1. 按[部署说明](../README.md)准备专用验收实例。给 `prepare.sh` 传入 `--external-attestation` 并将管理员公钥参数设为 `-`。用生成的上下文构建 `trustee-tdx` 后，运行 `shelter run -d --target tdx-interop --name trustee-e2e trustee-tdx`。该配置只包含 `tdx-interop`。实例首次启动时生成独立的验收管理员私钥，保存在 `/var/lib/trustee-shelter/identity/admin.key`。该模式由客户端/AS 验证 TDX，Shelter 的启动时证明是另一项检查。保留部署输出中的 `i-...`。
2. 准备支持 Intel TDX 的 `trustee-attester`。它来自 [openanolis/guest-components v1.8.0](https://github.com/openanolis/guest-components/tree/v1.8.0/attestation-agent/kbs_protocol)，不在 Trustee 服务端 RPM 中。在与来宾 ABI 兼容、已安装 Rust 1.88 和 Intel DCAP TDX 开发库的 x86_64 构建机上执行以下命令，仅将生成的可执行文件及其缺少的运行库放入来宾。运行 `ldd` 确认依赖齐全。

   ```sh
   git clone --branch v1.8.0 --depth 1 https://github.com/openanolis/guest-components.git
   cd guest-components
   cargo build --release --locked -p kbs_protocol --bin trustee-attester \
     --no-default-features --features bin,background_check,rust-crypto,tdx-attester
   ldd target/release/trustee-attester
   ```

3. 在来宾内安装 Python 3.9+、`certutil`（ALinux 软件包 `nss-tools`）、Chromium 及其运行库，并将 `trustee-attester` 放到 `PATH`。配方根文件系统为 8 GiB，Rust 编译和浏览器缓存可使用单独的临时盘。以下命令中的 `/mnt/test` 是已挂载且可执行的测试盘。在出网受限的实例上可预先准备对应架构的 wheel、浏览器及运行库。

   ```sh
   python3.11 -m venv /mnt/test/venv
   /mnt/test/venv/bin/pip install 'playwright==1.56.0'
   export PLAYWRIGHT_BROWSERS_PATH=/mnt/test/browsers
   /mnt/test/venv/bin/python -m playwright install --only-shell chromium
   ```

## 执行

用有权读取实例本地测试私钥的账号，在来宾内的 Trustee 源码目录运行。测试需要 `shelter/tests` 和相邻的 `shelter/guest/policy.rego`。有系统 Chromium 时可以加 `--chromium /path/to/chromium`。

```sh
/mnt/test/venv/bin/python shelter/tests/acceptance.py \
  --admin-key /var/lib/trustee-shelter/identity/admin.key \
  --instance-id "$ECS_INSTANCE_ID"
```

浏览器默认连接 `https://127.0.0.1:8082`，也支持 `--origin https://trustee.internal:8082`。脚本将该域名解析到回环地址，用实例 CA 建立临时 Chromium 信任库并校验证书。管理员私钥由页面在此浏览器中签名，管理员 JWT 只发往回环服务。原生客户端另建 RCAR 会话，使用同一个 CA 验证服务器。测试结束时清理浏览器配置。

默认 TDX 客户端是同一来宾内的独立进程。若要验收第二台 TDX 客户端，用 `--client /path/to/runner` 指定现有受控执行器。执行器接收唯一的资源路径，在客户端运行 `tdx-client.sh "$1"`，只将其标准输出及退出码返回。第二台客户端需信任服务器的公开 CA，并通过 `TRUSTEE_URL=https://trustee.internal:8082`、`TRUSTEE_CA_FILE=/path/to/ca.crt` 指向能通过 TLS 校验的服务端。执行器应原样保留拒绝取密时的非零退出码。

## 判定

| 检查 | 通过条件 |
| --- | --- |
| 服务与前端 | systemd 服务组和六个组件均 active，浏览器登录，健康页的四项服务均正常 |
| 策略和参考值 | 新建、回读、修改、删除独立 AS 策略；KBS 全局策略保存、回读；RVPS 新建、查询、删除独立测试参考值 |
| 取密与审计 | 同一个随机资源先经真实证明后收到 403；安装只授权该资源的临时策略后重新证明，返回 200；解密后 SHA-256 与上传的 48 字节随机资源完全一致，两次 GET 分别关联本次成功的 TDX 证明 |
| 资源、实例和退出 | 页面查询、文本/二进制上传及删除；找到指定 ECS 的活跃心跳，搜索、重置、刷新；退出后清除会话 |

临时策略要求 AS 签名的 EAR 中有受认可的 Intel TDX 硬件和关闭 DEBUG 的 TD，且路径与本次随机测试资源完全匹配。该输入验证平台取密互操作性，生产负载应另外配置经批准的启动度量和参考值。测试仅接受配方出厂的拒绝策略；取密结束后恢复原策略并删除测试资源。如测试进程被强杀或实例断电，请检查管理页中的资源策略，必要时恢复 `shelter/guest/policy.rego` 并删掉本轮测试对象。

在无 TDX 的本地环境，可运行 `--management-only` 验证真实管理页面与后端。该模式单独报告结果，跳过 systemd、TDX 证明、解密及其关联审计；不计入完整验收。
