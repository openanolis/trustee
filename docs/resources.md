# 资源管理和资源策略

## 资源管理

### 简介

Trustee除远程证明外，一个重要的功能是基于远程证明结果和密钥，进行机密资源数据的分发。例如，当某个TEE实例需要获取关键数据的解密密钥时，即可以将该解密密钥视作机密资源，上传至Trustee中，并在TEE实例中访问Trustee进行远程证明，在远程证明通过后将资源通过加密信道下载到本地。

#### 方法

**步骤一**：在Trustee中上传机密资源

调用Trustee API:  `POST /api/kbs/v0/resource`s , 将机密资源上传到Trustee中指定路径保存，例如将资源数据`"12345"` 上传到指定的路径 `my-repo/my-type/my-tag`中：

```shell
curl -k -X POST http://<gateway-host>:<port>/api/kbs/v0/resource/my-repo/my-type/my-tag  \
     -H 'Content-Type: application/octet-stream' \
     -H "Authorization: Bearer <token>" \
     -d "12345"
```

注意：路径必须是三段式的 `仓库名/类型名/标签`

上传完成后，可以在Trustee中对资源进行增加、删除、修改等操作（调用相关API）

**步骤二**：在机密/可信实例中安装机密数据客户端（confidential data hub）

```shell
yum install confidential-data-hub
```

**步骤三**：设置环境变量指定Trustee地址以供机密数据客户端读取

```shell
# IP地址设置为Trustee真实部署地址
export TRUSTEE_URL=http://127.0.0.1:8082/api
export AA_KBC_PARAMS=cc_kbc::$TRUSTEE_URL
```

**步骤四**：调用confidential data hub命令行工具获取资源

例如，使用如下命令获取步骤一中上传到`my-repo/my-type/my-tag`路径的资源：

```shell
RUST_LOG=off confidential-data-hub get-resource --resource-uri kbs://my-repo/my-type/my-tag | base64 -d
```

上述命令会将资源数据打印到终端上。

**步骤五**：审计资源获取记录和远程证明记录

在步骤四中，`confidential data hub`会首先调用AA进行密钥生成和远程证明，获得一个kbs的远程证明token（绑定了一个新生成的tee密钥对），再调用Trustee下载加密资源并解密。通过Trustee的资源请求审计API，可以查看资源获取记录和相关的远程证明记录。

## 资源策略

与远程证明策略类似，资源策略本质上也是一段用户可定制的代码，其功能用一句话概括来说就是“控制什么样的资源可以向什么样的客户端环境发放”

### 输入内容

根据OPA策略引擎要求，输入有两类：`input`和`data`，在资源策略验证中，分别是如下内容：

- `input`：远程证明结果令牌的Body Claims
- `data`：一次请求的资源路径，如：`{ "resource-path": "my-repo/my-type/tag" }`

### 输出内容

输出是否允许此次资源请求通过（true or false），例如`{ "allow": "true" }`

### 执行逻辑

资源策略有非常灵活的可定制空间，可以根据输入`input`的远程证明结果令牌Body Claims内容对客户端进行分类，根据输入`data`的三段式资源路径对资源进行分类，在执行逻辑中编写判断是否允许某类资源向某类客户端进行下发。

Trustee提供了一个默认策略，即检查客户端是否运行在一个通过了远程证明验证，且信任向量中的四个维度都是可信的环境中，如果是，就放行一切资源请求：


```
# Resource Policy (Default)
# -------------------------
#
# This default KBS resource policy decides whether a requester is allowed to
# access a resource based on the Attestation Claims (input) and the resource
# path (data). It is tailored for EAR tokens:
#
# - Resource path (data):
#   {
#     "resource-path": "<REPO>/<TYPE>/<TAG>"
#   }
#   The path is a string with three segments, e.g. "repo/key/prod".
#
# - Attestation Claims (input):
#   When using EAR tokens, the trustworthiness vector is expected under:
#     input.submods["cpu0"]["ear.trustworthiness-vector"]
#   where the trust vector contains (at least):
#     configuration, executables, file_system, hardware
#
# Default decision:
#   Allow only when cpu0 reports trusted levels for ALL the four dimensions
#   according to the current policy threshold (<= 32 by default):
#     configuration, executables, file_system, hardware.
#   Otherwise deny.
#
# Note:
# - If cpu0 is not present in the EAR claims, the request is denied.
# - You can further extend this file by adding platform recognizers based on
#   annotated-evidence (e.g. input.submods["cpu0"]["ear.veraison.annotated-evidence"].tdx)
#   or by adding per-repository rules.

package policy

import rego.v1

default allow = false

# ---------------------------
# Resource path helpers
# ---------------------------
resource_path := data["resource-path"]
path_parts := split(resource_path, "/")

is_repo(name) if { count(path_parts) == 3; path_parts[0] == name }
is_type(t)    if { count(path_parts) == 3; path_parts[1] == t }
is_tag(tag)   if { count(path_parts) == 3; path_parts[2] == tag }

# ---------------------------
# EAR helpers (cpu0-only)
# ---------------------------

# All four core dimensions must satisfy the trust threshold (<= 32)
core4_strict(tv) if {
	tv.configuration <= 32
	tv.executables <= 32
	tv.file_system <= 32
	tv.hardware <= 32
}

# ---------------------------
# Default decision
# ---------------------------

allow if {
	# cpu0 must exist
	s := input.submods["cpu0"]
	# cpu0 must carry a trustworthiness vector
	tv := s["ear.trustworthiness-vector"]
	# and it must satisfy the strict condition
	core4_strict(tv)
}
```