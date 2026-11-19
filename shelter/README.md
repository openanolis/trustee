# 用 Shelter 在阿里云 TDX ECS 启动 Trustee

在一台 ALinux 3/4 部署机上构建镜像并调用阿里云 API。阿里云创建的 **TDX ECS 就是运行 Trustee 的 TDVM**。使用此路径，部署机可以是普通 ECS。镜像包含 KBS、AS、RVPS、Gateway 和 Web 管理前端。[架构与信任边界](ARCHITECTURE.md)

**首次试用且暂无平台批准度量**，可直接按[互操作验收指南](tests/README.md)启动 `tdx-interop`，使用真实 TDX 客户端取密并检查管理页面。下面的 `production` 路径还会验证 Trustee 服务端的启动环境。

### 1. 准备部署机

- 安装带 `terraform-alicloud` 后端的 Shelter V2、配套运行时资产和 Terraform。使用 Shelter `6111b1a` 时，先在其源码目录执行 `git apply /绝对路径/trustee/shelter/compat/private-ecs-endpoint.patch`，使仅分配私网 IP 的实例能使用私网地址做启动证明。已包含这项修复的版本可直接编译。依次执行 `sudo make install-deps`、`make`、`sudo make install` 和 `make verify-system-dependencies`。以下命令还用到 Python 3、PyYAML、OpenSSL 和 GitHub CLI。
- 为运行 Shelter 的账号配置其阿里云 provider 身份，并选好可购买 TDX 规格的地域、可用区和可路由的 VPC/vSwitch。部署端需访问实例 TCP 8006，管理浏览器与取密客户端需访问 TCP 8082。给出各自的实际源 CIDR，云凭据仅配置在部署端。
- AS 通过所选地域的 VPC PCCS 获取 Intel DCAP 验证材料。默认使用 `https://sgx-dcap-server-vpc.<region>.aliyuncs.com/sgx/certification/v4/`，北京端点已在 ECS 验证。若使用自有 PCCS，可在准备上下文时传入 `--pccs-url https://pccs.example.internal:8081`，确保实例信任其 HTTPS 证书。
- 来宾需能解析并访问阿里云 VPC NTP（UDP 123）。首次启动等待时钟同步再签发实例证书，跨机客户端依赖正确的 UTC 时间验证证书和令牌。[阿里云 ECS 时间同步](https://help.aliyun.com/zh/ecs/user-guide/alibaba-cloud-ntp-server)
- 在策略负责人审核的 verifier 工作目录内准备 `token/ear/policies/opa/default.tdx-appraisal.json`，并设置 `ATTESTATION_CHALLENGE_CLIENT_WORK_DIR`。该策略约束平台启动度量、TCB 状态和调试属性。默认生产部署需要它。

在 Trustee 仓库根目录执行以下命令。管理员保管 Ed25519 私钥，构建机只需公钥。先设置 `REGION`、`ZONE`、`TDX_INSTANCE_TYPE`、`VPC_ID` 和 `VSWITCH_ID`。北京示例前三项依次是 `cn-beijing`、`cn-beijing-l`、`ecs.g8i.xlarge`。将下面三个示例 CIDR 依次替换为管理员、TDX 客户端、部署机的实际来源。

```bash
umask 077
keys=$(mktemp -d "$HOME/trustee-admin.XXXXXXXX")
openssl genpkey -algorithm ED25519 -out "$keys/admin.key"
openssl pkey -in "$keys/admin.key" -pubout -out "$keys/admin.pub"
rpms=$(mktemp -d)
gh release download v1.10.2 -R openanolis/trustee -D "$rpms" \
  -p 'trustee-1.10.2-1.al8.x86_64.rpm' \
  -p 'trustee-frontend-1.10.2-1.al8.x86_64.rpm'
ctx="$HOME/trustee-build"
bash shelter/prepare.sh "$ctx" "$keys/admin.pub" \
  192.0.2.1/32 198.51.100.1/32 203.0.113.1/32 \
  --rpm-dir "$rpms" --region "$REGION" --zone "$ZONE" \
  --instance-type "$TDX_INSTANCE_TYPE" --vpc-id "$VPC_ID" --vswitch-id "$VSWITCH_ID"
```

### 2. 构建一次，按需启动

```bash
shelter config validate -c "$ctx/shelter.yml"
shelter build -t trustee-tdx "$ctx"
shelter run --plan --target production trustee-tdx
shelter run -d --target production --name trustee-01 trustee-tdx
shelter inspect trustee-01
shelter attestation status trustee-01
```

创建第二台相同配置的实例时，可复用本地镜像并换一个实例名称，云端仍可能需要导入镜像。再次使用同一台实例，直接执行 `shelter start trustee-01`。变更镜像内的管理公钥或来源限制后要重新构建。镜像使用正式发布的后端和前端 RPM。[Trustee v1.10.2](https://github.com/openanolis/trustee/releases/tag/v1.10.2)

### 3. 登录、配置与取密

1. 将 `trustee.internal` 解析到实例可达的地址。在已登录阿里云 CLI 的部署机执行 `python3 shelter/fetch-ca.py "$REGION" "$INSTANCE_ID" > trustee-ca.pem`。它从该 ECS 启动串口提取实例 CA 公共证书。确认实例身份后，在管理浏览器和 TDX 客户端中信任该 CA。[ECS 串口输出 API](https://help.aliyun.com/zh/ecs/developer-reference/api-ecs-2014-05-26-getinstanceconsoleoutput/)
2. 打开 `https://trustee.internal:8082`，选择管理员的 Ed25519 私钥文件登录。进入“系统健康”确认 Gateway、AS、KBS 和 RVPS 全部正常。离开管理浏览器时点击“登出”，清除前端保存在浏览器中的登录信息。
3. 初始 KBS 策略拒绝取密。在“参考值服务”登记经审核的客户端度量，在“策略管理”配置 AS 证明策略和 KBS 资源策略，再到“资源管理”录入资源。客户端传三段路径 `仓库/类型/标签`。v1.10.2 的 KBS 策略匹配 `data["resource-path"]` 时要包含插件前缀，例如 `resource/仓库/类型/标签`。在“审计日志”核对本次证明与读取记录。

例如，使用带 TDX 支持的 `trustee-attester` 在客户端读取已授权的资源。该命令将获取的内容保存为本地文件。

```bash
set -o pipefail
umask 077
trustee-attester --url https://trustee.internal:8082 --cert-file trustee-ca.pem \
  get-resource --path "$REPOSITORY/$TYPE/$TAG" | base64 --decode > resource.bin
```

### 4. 验收与回收

真实验收脚本见[验收指南](tests/README.md)。请在专用实例执行，脚本会新建临时资源、策略与参考值，检查硬件客户端解密得到的内容，并操作管理页面。用于互操作验收的 `--external-attestation` 仍指定 ECS TDX 模式，其结果不包含 Shelter 对服务端 TDVM 的独立证明。生产环境使用上面的默认配置。

```bash
shelter stop trustee-01
shelter start trustee-01   # 保留同一实例和系统盘
# 完成备份、确定要释放环境时执行
shelter stop trustee-01
shelter rm trustee-01
```
