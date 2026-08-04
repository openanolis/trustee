# 远程证明

## 使用方法

**步骤一**：在一个机密/可信实例（例如Intel TDX VM，Hygon CSV3 VM等）中，安装`attestation-agent`：

```shell
yum install attestation-agent
```

**步骤二**：修改attestation-agent配置文件，指定Trustee地址 (`token_configs`字段)

```shell
cat << EOF > /etc/trustiflux/attestation-aget.toml
[token_configs]

[token_configs.coco_as]
url = "http://127.0.0.1:8081/api/as"

[token_configs.kbs]
url = "https://127.0.0.1:8081/api"

...
EOF
```

修改完毕后，需要重启AA：

```shell
systemctl restart attestation-agent
```

若不方便修改配置文件，或想要在不重启AA的前提下动态配置Trustee地址，也可通过环境变量设置：

```shell
export TRUSTEE_URL=http://127.0.0.1:8081/api
```

**步骤三**：触发远程证明

```shell
# 直接进行远程证明：
attestation-agent-client get-token --token-type coco_as
# 或生成一个RSA密钥对，并绑定至远程证明证据中，再进行证明：
attestation-agent-client get-token --token-type kbs
```

上述命令会和Trustee交互，最终获取一个EAR格式的远程证明结果令牌（JWT标准Base64编码，有效期五分钟），包含对客户端环境的验证评估报告，和解析后的远程证明证据内容。

## 参考值

参考值字段命名的本质是远程证明策略指定的。
在默认策略（id: default）下，Trustee提供了一套标准的参考值字段命名，如下：

### 度量值

各个度量值的参考值字段的名称不再包含特定平台类型前缀（如tpm, tdx等），统一为如下格式：

```json
{
    "measurement.grub.<algorithm>": ["<grub_digest>"],
    "measurement.shim.<algorithm>": ["<shim_digest>"],
    "measurement.initrd.<algorithm>": ["<initrd_digest>"],
    "measurement.kernel.<algorithm>": ["<kernel_digest>"],
    "measurement.kernel_cmdline.<algorithm>": ["<cmdline_digest>"],
    # <algorithm>的取值可以是SHA-1, SHA-256, SHA-384, SM-3...因平台而异
  
    "measurement.file.<file_path>": ["<file_hash>"]
}
```

OpenAnolis提供了一个简单易用的工具[cryptpilot](https://github.com/openanolis/cryptpilot)，用于对一个系统镜像一键计算出上述启动度量值的参考值（包括grub、shim、initrd、kernel、kernel_cmdline），具体方式参见文档[reference.md](./reference.md).

### Hygon TPM AK Credential 兼容路径

`Hygon TPM` 当前的 AK credential 接入方式与通用 TPM 保持一致，优先复用本地已经落地的 AK，而不修改 Trustee 现有的 `TPM PCA` 插件行为。

若 guest 侧存在如下条件：

- 环境变量 `KEYLIME_AGENT_UUID`
- 本地文件 `/var/lib/keylime/agent_data.json`

则 `Hygon TPM attester` 会优先从 `agent_data.json` 读取已激活的 AK（期望为 `SM2 + SM3`），直接使用该 AK 生成 quote，并在 evidence 中携带 `keylime_agent_uuid`。

随后，Trustee 侧 `Hygon TPM verifier` 会使用该 UUID 向 Keylime registrar 查询 AK/EK 信息，并校验：

- evidence 中的 EK 证书是否与 registrar 一致
- evidence 中的 AK 公钥是否与 registrar 中的 `aik_tpm` 一致

如果本地不存在可复用的 AK，`Hygon TPM attester` 会回退为临时生成新的 SM2 AK，仅完成主链路 quote 证明，不执行 registrar 绑定校验。

### SEV-SNP + SVSM vTPM 动态度量

当 SNP guest 使用 Coconut SVSM vTPM，且 guest 内核提供 `tpm_svsm` 与 TSM SVSM attestation ABI 时，Attestation Agent 会把 SNP 作为主证据、TPM Quote 作为附加设备证据，并把 AA 动态事件扩展到 vTPM PCR。

Trustee 在 Attestation Service 核心层验证这组组合证据，因此经 KBS、
直接访问 RESTful AS 或直接访问 gRPC AS 都遵循相同的安全语义：

1. 验证 VMPL0 SNP report 的签名、证书链和 challenge 绑定；其中 `REPORT_DATA = SHA-512(nonce || vTPM manifest)`。
2. 验证 SNP runtime data 覆盖的 TPM evidence 与本次提交给 AS 的 TPM evidence 完全一致，并确认两者使用相同的基础 runtime data，阻止替换或跨 guest 拼接证据。
3. 验证 manifest 中的 EK `TPMT_PUBLIC` 与 TPM evidence 携带的 EK 完全一致。
4. 验证 TPM Quote 的签名、nonce、PCR digest，并回放 UEFI 启动日志和 AA 动态事件日志，逐项比对 Quote 中的 PCR。

直连 RESTful AS 或 gRPC AS 时，应在同一个请求中提交 SNP、TPM 两条
`verification_requests`。SNP 的 structured runtime data 使用
`additional-evidence` 携带序列化后的 TPM evidence；TPM 的 structured runtime
data 则是去掉 `additional-evidence` 后的同一组基础字段。单独提交 SNP 或 TPM
证据的既有用法不受影响；只有同一次 evaluation 同时包含二者时才强制上述组合绑定。
生产环境应先通过 AS challenge API 获取签名 challenge，并把其中的 JWT 作为
`challenge_token` 放入这组基础 runtime data，使 AS 同时校验 challenge 的签名和有效期。

Keylime 是可选增强：没有 `keylime_agent_uuid` 时，上述主链路仍会完整执行；只有 evidence 提供 UUID 时，TPM verifier 才查询 registrar，并额外验证已激活 AK 与 EK 的绑定关系。SVSM vTPM 的 EK 通常没有厂商证书，因此该路径优先比较 registrar 的 `ek_tpm` 与 evidence 的 EK 公钥；物理 TPM 仍兼容 EK 证书比较。

### 平台特定

平台特定的证据字段内容已经在Trustee内部验证硬件证书和硬件签名时做过了一轮验证，确保其真实可信，如果想要在远程证明策略中对关注的字段再次做一次自定义的验证，就需要设置对应的参考值。

例如，若在远程证明策略中要求验证tdx xfam配置的值符合预期，即若策略中有如下一句：

```
input.tdx.quote.body.xfam in data.reference["tdx.xfam"]
```

则需要在参考值中设置如下字段：

```json
{
  "tdx.xfam": ["xxx"]
}
```

同理，若在 `Hygon TPM` 策略中要求验证 TPM 固件版本或 EK 证书签发方，则可使用如下形式：

```rego
input.hygontpm["quote.firmware_version"] in data.reference["hygontpm.firmware_version"]
input.hygontpm.EK_cert_issuer.OU in data.reference["hygontpm.ek_cert_issuer_ou"]
```

对应的参考值示例：

```json
{
  "hygontpm.firmware_version": ["12345678"],
  "hygontpm.ek_cert_issuer_ou": ["HYGON TPM EK CA"]
}
```

## 远程证明策略

远程证明策略，其本质上是一段用户可定制的代码，用于控制证据内容和参考值比对的具体要求：

### 输入内容

根据OPA策略引擎要求，输入有两类：input和data，在远程证明策略验证中，分别是如下内容：

- `input`：解析后的远程证明证据内容，即Attestation Result Token中的`submods.cpu0.ear.veraison.annotated-evidence`值
- `data` ：参考值Map


### 输出内容

包含四个维度（硬件、可执行程序、配置、文件系统）评估结果的信任向量

- "configuration"：描述系统配置的可信度，例如`kernel cmdline`等
- "executables"：描述系统可执行程序的可信度，例如`shim`、`grub`、`kernel`等
- "file_system"：描述文件系统的可信度，例如`rootfs`、自定义度量文件等
- "hardware"：描述硬件的可信度，例如TDX、TPM、CSV硬件属性等

信任向量的值用IETF RATS式标准中的AR4SI draft来表示评估结果：

- 0~32：可信，对应 `valid`
- 33~96：警告，对应 `warning`
-  97~127：禁用，对应 `contraindicated`

### 执行逻辑

首先，将四个维度信任向量初始值设置为 97~127（禁用），然后分成四个模块来分别判定其可信程度，判定方法如下：

- 若`kernel cmdline`度量值等于参考值，则将`configuration`设置为0~32（可信）
- 若`shim`、`grub`、`kernel`、`initrd`的度量值等于参考值，则将`executables`设置为0~32（可信）
- 若AAEL中记录的文件度量值等于参考值，则将`file_system`设置为0~32（可信）
- 若关注的硬件特定字段的值（例如安全版本号，闭源固件度量值等）等于参考值，则将`hardware`设置为0~32（可信）

对于 `Hygon TPM`，默认策略中的启动链比对沿用通用 `measurement.*` 键空间，但通常使用 `SM-3` 作为算法后缀，例如 `measurement.kernel.SM-3`。

如果不关注其中某个维度，例如没有关注的硬件特定字段值（因为Trustee在远程证明策略验证之前已经对硬件证据进行了一轮默认签名和证书验证），也可以直接将某个维度默认设置成0~32（可信）或33~96（警告）

### 举例

下面是从default策略中截取的一段TDX机器的验证策略（完整默认策略见[attestation-service/src/token/ear_default_policy_cpu.rego](../attestation-service/src/token/ear_default_policy_cpu.rego)）：

```
package policy

import rego.v1

default executables := 33
default hardware := 97
default configuration := 36
default file_system := 35

executables := 3 if {
	# Check the kernel, initrd, shim and grub measurements for any supported algorithm
	validate_boot_measurements_uefi_event_log(input.tdx.uefi_event_logs)
}

hardware := 2 if {
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"

	# Check TDX Module version and its hash. Also check OVMF code hash.
	input.tdx.quote.body.mr_seam in data.reference["tdx.mr_seam"]
	input.tdx.quote.body.tcb_svn in data.reference["tdx.tcb_svn"]
	input.tdx.quote.body.mr_td in data.reference["tdx.mr_td"]
}

configuration := 2 if {
	# Check the TD has the expected attributes (e.g., debug not enabled) and features.
	input.tdx.td_attributes.debug == false
	input.tdx.quote.body.xfam in data.reference["tdx.xfam"]

	# Check kernel command line parameters have the expected value for any supported algorithm
	validate_kernel_cmdline(input.tdx.ccel, input.tdx.ccel.kernel_cmdline)
}

file_system := 2 if {
	# Check measured files - iterate through all file measurements
	validate_aael_file_measurements(input.tdx.uefi_event_logs)
}
```
