# 远程证明结果令牌

一个典型的Attestation结果令牌解析出来的Body Claims如下（以TDX为例）：

```json
{
  "eat_profile": "tag:github.com,2024:confidential-containers/Trustee",
  "iat": 1761119308,
  "exp": 1761119608,
  "ear.verifier-id": {
    "developer": "https://confidentialcontainers.org",
    "build": "attestation-service 0.1.0"
  },
  "submods": {
    "cpu0": {
      "ear.status": "contraindicated",
      "ear.trustworthiness-vector": {
        "configuration": 36,
        "executables": 33,
        "file-system": 35,
        "hardware": 97
      },
      "ear.appraisal-policy-id": "default",
      "ear.veraison.annotated-evidence": {
        "tdx": {
          ...
          "uefi_event_logs": [
            {
              "details": {...},
              "digests": [
                {
                  "alg": "SHA-256",
                  "digest": "..."
                }
              ],
              "event": "...",
              "index": 16,
              "type_name": "EV_EVENT_TAG"
            },
            ...
          ]
        }
      }
    }
  }
}
```

需要关注的字段主要在 `submods.cpu0` 中：

### `submods.cpu0.ear.status`

远程证明结果的整体评估情况，有如下三种值：

  - `valid`：表示验证目标可信。当且仅当信任向量中每个维度都为可信时才会出现
  - `warning`：表示验证目标大体可信，但有部分警告。只要信任向量中有一个维度是警告值，就会出现
  - `contraindicated`：表示验证目标不可信。只要信任向量中有一个维度是该值，就会出现

### `submods.cpu0.ear.trustworthiness-vector`

信任向量，承载分维度评估远程证明对象的可信情况的结果，当前包含如下四个维度：

  - `hardware`：表明硬件可信情况，例如：TDX VM是否是真实运行在由Intel芯片背书的加密内存内，或者TPM芯片是否是真实可信的等。
  - `executables`：表明可执行程序的可信情况，例如：shim度量值、kernel度量值、initrd度量值等。
  - `configuration`：表明系统配置的可信情况，例如：kernel cmdline等
  - `file-system`：表明文件系统的可信情况，例如：AAEL中记录的自定义文件度量值等

信任向量的值用 IETF RATS 式标准中的 AR4SI draft 来表示评估结果：
    - 0~32：可信，对应 `valid`
    - 33~96：警告，对应 `warning`
    - 97~127：禁用，对应 `contraindicated`

### `submods.cpu0.ear.appraisal-policy-id`

此次验证使用的远程证明策略 ID，默认为 `default`

### `submods.cpu0.ear.veraison.annotated-evidence`

这个字段的内容是解析后的远程证明证据内容，包含度量值等信息，不同的平台类型有不同的内容，具体TPM、TDX和CSV平台上的例子见附录

#### `submods.cpu0.ear.veraison.annotated-evidence.tdx.uefi_event_logs`

这个字段是动态度量Eventlog值，是一个数组，每一个条目包含两项：
  - `details`：度量内容的描述
  - `digests`：这一条Event的哈希值
CCEL启动度量值（grub、shim、initrd、kernel）和AAEL动态度量值就记录在这个Eventlog数组中。


## 从令牌中读取启动度量值

### TPM平台

对于TPM平台，启动度量值可以直接在`annotated-evidence`字段中读取，分别是如下几项：

```json
"kernel_cmdline": "grub_kernel_cmdline (hd0,gpt3)/boot/vmlinuz-5.10.134-19.1.al8.x86_64 root=UUID=33b46ac5-7482-4aa5-8de0-60ab4c3a4c78 ro rhgb quiet cgroup.memory=nokmem crashkernel=0M-2G:0M,2G-8G:192M,8G-128G:256M,128G-376G:384M,376G-:448M spec_rstack_overflow=off vring_force_dma_api kfence.sample_interval=100 kfence.booting_max=0-2G:0,2G-32G:2M,32G-:32M preempt=none biosdevname=0 net.ifnames=0 console=tty0 console=ttyS0,115200n8 noibrs nvme_core.io_timeout=4294967295 nvme_core.admin_timeout=4294967295 cryptomgr.notests rcupdate.rcu_cpu_stall_timeout=300\u0000",
"measurement.grub.SHA1": "94b31eb049948918ce988e0ef1a80521db3a01c8",
"measurement.initrd.SHA1": "65f1c5ddbaff5a71d0ba9031cba9bcb3162428c8",
"measurement.kernel.SHA1": "0319d6c6472e168dd8081622b2ee5a88ce977457",
"measurement.kernel_cmdline.SHA1": "bd33fab641f48cd1c31ba1fa8dc8fa9b392834c2",
"measurement.shim.SHA1": "54377e45046bd7e9d7734a9d693dc3e9e529f2da",
```

### TDX/CSV 平台

对于 TDX 平台和 CSV 平台，启动度量值记录在 `annotated-evidence.uefi_event_logs` 数组中，需要按如下条件搜索读取：

  - grub：`type_name` 值为 `EV_EFI_BOOT_SERVICES_APPLICATION` 且 `details.device_paths` 包含字符串 "grub"
  - shim：`type_name` 值为 `EV_EFI_BOOT_SERVICES_APPLICATION` 且 `details.device_paths` 包含字符串 "shim"
  - kernel：`type_name` 值为 `EV_IPL` 且 `details.string` 包含字符串 "Kernel"
  - Initrd：`type_name` 值为 `EV_IPL` 且 `details.string` 包含字符串 "Initrd"
  - kernel cmdline：`type_name` 值为 `EV_IPL` 且 `details.string` 的前缀是 `grub_cmd linux`、`kernel_cmdline`、`grub_kernel_cmdline` 之一

例如下面这一项就是 Kernel 的度量值：

```json
{
  "details": {
    "string": "grub_linuxefi Kernel"
  },
  "digests": [
    {
      "alg": "SHA-384",
      "digest": "7ecde58258fb08dfd147cfdba2443ecfeae8b97fed8efe0cee199cd71dcc2fb7ff3d23e7ebcb24965186524c9904b84c"
    }
  ],
  "event": "Z3J1Yl9saW51eGVmaSBLZXJuZWwAbA==",
  "index": 3,
  "type_name": "EV_IPL"
}
```

例如下面这一项是 kernel cmdline 的度量值（`details.string` 字段中显示了 kernel cmdline 配置的原始内容）：

```json
{
  "details": {
    "string": "grub_kernel_cmdline (hd0,gpt3)/boot/vmlinuz-5.10.134-19.1.al8.x86_64 root=UUID=33b46ac5-7482-4aa5-8de0-60ab4c3a4c78 ro rhgb quiet cgroup.memory=nokmem crashkernel=0M-2G:0M,2G-8G:192M,8G-128G:256M,128G-376G:384M,376G-:448M spec_rstack_overflow=off vring_force_dma_api kfence.sample_interval=100 kfence.booting_max=0-2G:0,2G-32G:2M,32G-:32M preempt=none biosdevname=0 net.ifnames=0 console=tty0 console=ttyS0,115200n8 noibrs nvme_core.io_timeout=4294967295 nvme_core.admin_timeout=4294967295 cryptomgr.notests rcupdate.rcu_cpu_stall_timeout=300"
  },
  "digests": [
    {
      "alg": "SHA-384",
      "digest": "6a3d314eb16073a6c426173723c0a57a1e5c4efe9b355730d2c80be1026f8d03493355c5077c81f69fa05571406b96f8"
    }
  ],
  "event": "Z3J1Yl9rZXJuZWxfY21kbGluZSAoaGQwLGdwdDMpL2Jvb3Qvdm1saW51ei01LjEwLjEzNC0xOS4xLmFsOC54ODZfNjQgcm9vdD1VVUlEPTMzYjQ2YWM1LTc0ODItNGFhNS04ZGUwLTYwYWI0YzNhNGM3OCBybyByaGdiIHF1aWV0IGNncm91cC5tZW1vcnk9bm9rbWVtIGNyYXNoa2VybmVsPTBNLTJHOjBNLDJHLThHOjE5Mk0sOEctMTI4RzoyNTZNLDEyOEctMzc2RzozODRNLDM3NkctOjQ0OE0gc3BlY19yc3RhY2tfb3ZlcmZsb3c9b2ZmIHZyaW5nX2ZvcmNlX2RtYV9hcGkga2ZlbmNlLnNhbXBsZV9pbnRlcnZhbD0xMDAga2ZlbmNlLmJvb3RpbmdfbWF4PTAtMkc6MCwyRy0zMkc6Mk0sMzJHLTozMk0gcHJlZW1wdD1ub25lIGJpb3NkZXZuYW1lPTAgbmV0LmlmbmFtZXM9MCBjb25zb2xlPXR0eTAgY29uc29sZT10dHlTMCwxMTUyMDBuOCBub2licnMgbnZtZV9jb3JlLmlvX3RpbWVvdXQ9NDI5NDk2NzI5NSBudm1lX2NvcmUuYWRtaW5fdGltZW91dD00Mjk0OTY3Mjk1IGNyeXB0b21nci5ub3Rlc3RzIHJjdXBkYXRlLnJjdV9jcHVfc3RhbGxfdGltZW91dD0zMDAAXw==",
  "index": 3,
  "type_name": "EV_IPL"
}
```
grub、shim、initrd的度量值类似，不再赘述


## 从令牌中读取AAEL度量值

无论是TPM、TDX、CSV平台，AA动态度量值都记录在`annotated-evidence.uefi_event_logs`数组中，搜索方法如下：

- 满足 `type_name` 值为 `EV_EVENT_TAG`，且 `details.unicode_name` 为 `AAEL`、`details.data.domain` 为 `file`。

例如 `/etc/trustiflux/attestation-agent.toml` 这个配置文件的度量值就是 `uefi_event_logs` 中的下面这一项：

```json
{
  "details": {
    "data": {
      "content": "2e4192c9979f2cce05194562ba0923aea302c43021cd7cf91852121ae1d61d24",
      "domain": "file",
      "operation": "/etc/trustiflux/attestation-agent.toml"
    },
    "string": "file /etc/trustiflux/attestation-agent.toml 2e4192c9979f2cce05194562ba0923aea302c43021cd7cf91852121ae1d61d24",
    "unicode_name": "AAEL"
  },
  "digests": [
    {
      "alg": "SHA-256",
      "digest": "017cf35926f9f54801a07fd7af60218cded3a193f2dda1e84a4b5d25d19548d5"
    }
  ],
  "event": "TEVBQWwAAABmaWxlIC9ldGMvdHJ1c3RpZmx1eC9hdHRlc3RhdGlvbi1hZ2VudC50b21sIDJlNDE5MmM5OTc5ZjJjY2UwNTE5NDU2MmJhMDkyM2FlYTMwMmM0MzAyMWNkN2NmOTE4NTIxMjFhZTFkNjFkMjQ=",
  "index": 16,
  "type_name": "EV_EVENT_TAG"
}
```

注意：与启动组件度量不同，对于文件度量值项，文件本身的度量值是 `details.data.content`，而 `digests.digest` 是 Event 本身的度量值（即“度量动作的度量值”）。因此在设置参考值时，需要以 `details.data.content` 作为度量值基准。


# 附录

下面给出真实测试中，TPM、TDX、CSV三个平台上，Attestation结果令牌中`submods.cpu0.ear.veraison.annotated-evidence`值的内容

## TPM

`submods.cpu0.ear.veraison.annotated-evidence.tpm`值：

```json
{
  "report_data": "0000000000000000000000000000000000000000000000000000000000000000",
  "runtime_data_claims": null,
  "tpm": {
    "EK_cert_issuer": {
      "C": "CN",
      "CN": "Aliyun TPM EKMF CA",
      "O": "Aliyun",
      "OU": "Aliyun TPM Endorsement Key Manufacture CA"
    },
    "kernel_cmdline": "grub_kernel_cmdline (hd0,gpt3)/boot/vmlinuz-5.10.134-19.1.al8.x86_64 root=UUID=33b46ac5-7482-4aa5-8de0-60ab4c3a4c78 ro rhgb quiet cgroup.memory=nokmem crashkernel=0M-2G:0M,2G-8G:192M,8G-128G:256M,128G-376G:384M,376G-:448M spec_rstack_overflow=off vring_force_dma_api kfence.sample_interval=100 kfence.booting_max=0-2G:0,2G-32G:2M,32G-:32M preempt=none biosdevname=0 net.ifnames=0 console=tty0 console=ttyS0,115200n8 noibrs nvme_core.io_timeout=4294967295 nvme_core.admin_timeout=4294967295 cryptomgr.notests rcupdate.rcu_cpu_stall_timeout=300\u0000",
    "measurement.grub.SHA-1": "94b31eb049948918ce988e0ef1a80521db3a01c8",
    "measurement.initrd.SHA-1": "65f1c5ddbaff5a71d0ba9031cba9bcb3162428c8",
    "measurement.kernel.SHA-1": "0319d6c6472e168dd8081622b2ee5a88ce977457",
    "measurement.kernel_cmdline.SHA-1": "bd33fab641f48cd1c31ba1fa8dc8fa9b392834c2",
    "measurement.shim.SHA1": "54377e45046bd7e9d7734a9d693dc3e9e529f2da",
    "quote.clock_info": "5287931517",
    "quote.firmware_version": "2312323638123443766",
    "quote.signer": "000b9fd23f6fd22e8affb0d097b9d0ee2d974ddd1be1f5fade89312c6909aec41564",
    "uefi_event_logs": [
      {
        "details": {
          "data": {
            "content": "6c7257e415797df965e36abf82e57ce014be03742826205d120857140a44dd76",
            "domain": "file",
            "operation": "/usr/local/bin/attestation-agent"
          },
          "string": "file /usr/local/bin/attestation-agent 6c7257e415797df965e36abf82e57ce014be03742826205d120857140a44dd76",
          "unicode_name": "AAEL"
        },
        "digests": [
          {
            "alg": "SHA-256",
            "digest": "a0a03d522d0491f413ac60e3439cd25676de3618fb2fe1e72440fde7beb433f3"
          }
        ],
        "event": "TEVBQWYAAABmaWxlIC91c3IvbG9jYWwvYmluL2F0dGVzdGF0aW9uLWFnZW50IDZjNzI1N2U0MTU3OTdkZjk2NWUzNmFiZjgyZTU3Y2UwMTRiZTAzNzQyODI2MjA1ZDEyMDg1NzE0MGE0NGRkNzY=",
        "index": 16,
        "type_name": "EV_EVENT_TAG"
      },
      {
        "details": {
          "data": {
            "content": "2e4192c9979f2cce05194562ba0923aea302c43021cd7cf91852121ae1d61d24",
            "domain": "file",
            "operation": "/etc/trustiflux/attestation-agent.toml"
          },
          "string": "file /etc/trustiflux/attestation-agent.toml 2e4192c9979f2cce05194562ba0923aea302c43021cd7cf91852121ae1d61d24",
          "unicode_name": "AAEL"
        },
        "digests": [
          {
            "alg": "SHA-256",
            "digest": "017cf35926f9f54801a07fd7af60218cded3a193f2dda1e84a4b5d25d19548d5"
          }
        ],
        "event": "TEVBQWwAAABmaWxlIC9ldGMvdHJ1c3RpZmx1eC9hdHRlc3RhdGlvbi1hZ2VudC50b21sIDJlNDE5MmM5OTc5ZjJjY2UwNTE5NDU2MmJhMDkyM2FlYTMwMmM0MzAyMWNkN2NmOTE4NTIxMjFhZTFkNjFkMjQ=",
        "index": 16,
        "type_name": "EV_EVENT_TAG"
      }
    ]
  }
}
```

## TDX

`submods.cpu0.ear.veraison.annotated-evidence.tdx`值：

```json
{
  "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "init_data_claims": null,
  "report_data": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "runtime_data_claims": null,
  "tdx": {
    "quote": {
      "body": {
        "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "mr_seam": "1cc6a17ab799e9a693fac7536be61c12ee1e0fabada82d0c999e08ccee2aa86de77b0870f558c570e7ffe55d6d47fa04",
        "mr_servicetd": "383c87d3bbb047b2d171eaca95312ede99f258088dc788f6ae2ccf8b6dd848fe8d47629e08b3f6cbd4a00dd47a5a033d",
        "mr_td": "157768a71a6a31f5561978c4cde665809d22976ef5dead2952839b7b3ea23b6c2931c9148fe1d117c99faefac18bb73b",
        "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "report_data": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "rtmr_0": "1f2059d803858927174358d9addcb4cab878d4aa4294d0c067b1e6bfe5dd71289fa2f2ccc05e0df9274d229ec9f535af",
        "rtmr_1": "5b7029f90494af5c2df867759979ce1ada00bb71d9c698a3941debed65123cf5baaec906ba5e85c55715a1399973d64e",
        "rtmr_2": "feebe81bf2c8d15e445c87051f34c2aa33e48e2bc1510cfb4227c1411c6a87b019a64da431c369cd19f0ce85e7001ce7",
        "rtmr_3": "af6ca7c358fe6f3109c1c0ea4f4738969f20765a604aea195103b6ce664879503d834ff4176bb423d7c87002ec77e7f1",
        "seam_attributes": "0000000000000000",
        "tcb_svn": "05010200000000000000000000000000",
        "td_attributes": "0000001000000000",
        "tee_tcb_svn2": "05010200000000000000000000000000",
        "xfam": "e742060000000000"
      },
      "header": {
        "att_key_type": "0200",
        "reserved": "00000000",
        "tee_type": "81000000",
        "user_data": "cbaa6853ed613001a9ca59f1508861e000000000",
        "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
        "version": "0500"
      },
      "size": "88020000",
      "type": "0300"
    },
    "uefi_event_logs": [
      {
        "details": {
          "string": "TdxTable"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "951b045980c718ed0f6909c99e159831ea81abd818f8b761412ca2725b5803363e7990365390419dc58dfb789968a3b2"
          }
        ],
        "event": "CVRkeFRhYmxlAAEAAAAAAAAAr5a7k/K5uE6UYuC6dFZCNgCQgAAAAAAA",
        "index": 1,
        "type_name": "EV_EFI_HANDOFF_TABLES2"
      },
      {
        "details": {
          "string": "Fv(XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "5a9a6faadec79debc1d35d4ce1d2d55f1089f1db50b0ad5eaa449112f3cdf4a5d08b2f4ebb38365fde7a347470e63a89"
          }
        ],
        "event": "KUZ2KFhYWFhYWFhYLVhYWFgtWFhYWC1YWFhYLVhYWFhYWFhYWFhYWCkAAADA/wAAAAAAAAQAAAAAAA==",
        "index": 1,
        "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
      },
      {
        "details": {
          "unicode_name": "SecureBoot",
          "unicode_name_length": 10,
          "variable_data": "AA==",
          "variable_data_length": 1,
          "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "cfa4e2c606f572627bf06d5669cc2ab1128358d27b45bc63ee9ea56ec109cfafb7194006f847a6a74b5eaed6b73332ec"
          }
        ],
        "event": "Yd/ki8qT0hGqDQDgmAMrjAoAAAAAAAAAAQAAAAAAAABTAGUAYwB1AHIAZQBCAG8AbwB0AAA=",
        "index": 1,
        "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG"
      },
      {
        "details": {
          "unicode_name": "PK",
          "unicode_name_length": 2,
          "variable_data": "",
          "variable_data_length": 0,
          "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "6f2e3cbc14f9def86980f5f66fd85e99d63e69a73014ed8a5633ce56eca5b64b692108c56110e22acadcef58c3250f1b"
          }
        ],
        "event": "Yd/ki8qT0hGqDQDgmAMrjAIAAAAAAAAAAAAAAAAAAABQAEsA",
        "index": 1,
        "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG"
      },
      {
        "details": {
          "unicode_name": "KEK",
          "unicode_name_length": 3,
          "variable_data": "",
          "variable_data_length": 0,
          "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "d607c0efb41c0d757d69bca0615c3a9ac0b1db06c557d992e906c6b7dee40e0e031640c7bfd7bcd35844ef9edeadc6f9"
          }
        ],
        "event": "Yd/ki8qT0hGqDQDgmAMrjAMAAAAAAAAAAAAAAAAAAABLAEUASwA=",
        "index": 1,
        "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG"
      },
      {
        "details": {
          "unicode_name": "db",
          "unicode_name_length": 2,
          "variable_data": "",
          "variable_data_length": 0,
          "variable_name": "cbb219d7-3a3d-9645-a3bc-dad00e67656f"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "08a74f8963b337acb6c93682f934496373679dd26af1089cb4eaf0c30cf260a12e814856385ab8843e56a9acea19e127"
          }
        ],
        "event": "y7IZ1zo9lkWjvNrQDmdlbwIAAAAAAAAAAAAAAAAAAABkAGIA",
        "index": 1,
        "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG"
      },
      {
        "details": {
          "unicode_name": "dbx",
          "unicode_name_length": 3,
          "variable_data": "",
          "variable_data_length": 0,
          "variable_name": "cbb219d7-3a3d-9645-a3bc-dad00e67656f"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "18cc6e01f0c6ea99aa23f8a280423e94ad81d96d0aeb5180504fc0f7a40cb3619dd39bd6a95ec1680a86ed6ab0f9828d"
          }
        ],
        "event": "y7IZ1zo9lkWjvNrQDmdlbwMAAAAAAAAAAAAAAAAAAABkAGIAeAA=",
        "index": 1,
        "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG"
      },
      {
        "details": {},
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0"
          }
        ],
        "event": "AAAAAA==",
        "index": 1,
        "type_name": "EV_SEPARATOR"
      },
      {
        "details": {
          "string": "ACPI DATA"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "bb7d99270d16cebb10e5c29a6bfe013b0ba428d75d705767243b67a1a6f6d11eb70ea63fc922d0d837c81877dddf0945"
          }
        ],
        "event": "QUNQSSBEQVRB",
        "index": 1,
        "type_name": "EV_POST_CODE"
      },
      {
        "details": {
          "string": "etc/table-loader"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "42dab56c6235bf3938b888da9030587c1d18a814c288a0db728eacfc80dddbed79610dc9a7dbfdb3046d6cdea5b2c924"
          }
        ],
        "event": "ZXRjL3RhYmxlLWxvYWRlcgA=",
        "index": 1,
        "type_name": "EV_PLATFORM_CONFIG_FLAGS"
      },
      {
        "details": {
          "string": "etc/acpi/rsdp"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "c495e0ba2d86ccc2d5dd5f48a8484939a25d1561e8e302b7cf6e07564757653a9dd25ea164e8a437b82e1cdb00480400"
          }
        ],
        "event": "ZXRjL2FjcGkvcnNkcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "index": 1,
        "type_name": "EV_PLATFORM_CONFIG_FLAGS"
      },
      {
        "details": {
          "string": "etc/tpm/log"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "69fca46943118a952e4f165e122a47f2b7b5336fa8fa1674a26437d183a7e947f15a4a0afabece6d6b28e3c84f60fac2"
          }
        ],
        "event": "ZXRjL3RwbS9sb2cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "index": 1,
        "type_name": "EV_PLATFORM_CONFIG_FLAGS"
      },
      {
        "details": {
          "string": "etc/acpi/tables"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "e5fb8efe8b068b4337f6e83b51978b2300ac3ec0ac4004e56ba2d5bbbb58dced4a7b154db76fe6f5b71ae92d24be226b"
          }
        ],
        "event": "ZXRjL2FjcGkvdGFibGVzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "index": 1,
        "type_name": "EV_PLATFORM_CONFIG_FLAGS"
      },
      {
        "details": {
          "unicode_name": "BootOrder",
          "unicode_name_length": 9,
          "variable_data": "AAABAAIAAwAEAA==",
          "variable_data_length": 10,
          "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "ede24e3f9f14bc8cfda8dd79f01a07e453f2384fe832231c16d26eab8b05eb7b302fc1f4ac609f7495da4212d0e442ff"
          }
        ],
        "event": "Yd/ki8qT0hGqDQDgmAMrjAkAAAAAAAAACgAAAAAAAABCAG8AbwB0AE8AcgBkAGUAcgAAAAEAAgADAAQA",
        "index": 2,
        "type_name": "EV_EFI_VARIABLE_BOOT"
      },
      {
        "details": {
          "unicode_name": "Boot0000",
          "unicode_name_length": 8,
          "variable_data": "CQEAACwAVQBpAEEAcABwAAAABAcUAMm9uHzr+DRPquo+5K9lFqEEBhQAIaosRhR2A0WDboq29GYjMX//BAA=",
          "variable_data_length": 62,
          "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "23ada07f5261f12f34a0bd8e46760962d6b4d576a416f1fea1c64bc656b1d28eacf7047ae6e967c58fd2a98bfa74c298"
          }
        ],
        "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAPgAAAAAAAABCAG8AbwB0ADAAMAAwADAACQEAACwAVQBpAEEAcABwAAAABAcUAMm9uHzr+DRPquo+5K9lFqEEBhQAIaosRhR2A0WDboq29GYjMX//BAA=",
        "index": 2,
        "type_name": "EV_EFI_VARIABLE_BOOT"
      },
      {
        "details": {
          "unicode_name": "Boot0001",
          "unicode_name_length": 8,
          "variable_data": "AQAAACIAVQBFAEYASQAgAEYAbABvAHAAcAB5AAAAAgEMANBBAwoAAAAAAQEGAAABAgEMANBBBAYAAAAAf/8EAE6sCIERn1lNhQ7iGlIsWbI=",
          "variable_data_length": 80,
          "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "83ec503357f82671fe2719e5692fb9cc891396c3a06c6da660efbeef9f5a5ebbfc5c559d52fa57ee24b4e721e61dddd2"
          }
        ],
        "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAUAAAAAAAAABCAG8AbwB0ADAAMAAwADEAAQAAACIAVQBFAEYASQAgAEYAbABvAHAAcAB5AAAAAgEMANBBAwoAAAAAAQEGAAABAgEMANBBBAYAAAAAf/8EAE6sCIERn1lNhQ7iGlIsWbI=",
        "index": 2,
        "type_name": "EV_EFI_VARIABLE_BOOT"
      },
      {
        "details": {
          "unicode_name": "Boot0002",
          "unicode_name_length": 8,
          "variable_data": "AQAAACIAVQBFAEYASQAgAEYAbABvAHAAcAB5ACAAMgAAAAIBDADQQQMKAAAAAAEBBgAAAQIBDADQQQQGAQAAAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
          "variable_data_length": 84,
          "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "5d21e8d8f50702b47241c00a68086173658dfe95796af75a9667bd318595c48e94b7891a27ed4052b5ef01ba97a2b205"
          }
        ],
        "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAVAAAAAAAAABCAG8AbwB0ADAAMAAwADIAAQAAACIAVQBFAEYASQAgAEYAbABvAHAAcAB5ACAAMgAAAAIBDADQQQMKAAAAAAEBBgAAAQIBDADQQQQGAQAAAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
        "index": 2,
        "type_name": "EV_EFI_VARIABLE_BOOT"
      },
      {
        "details": {
          "unicode_name": "Boot0003",
          "unicode_name_length": 8,
          "variable_data": "AQAAACYAVQBFAEYASQAgAEEAbABpAGIAYQBiAGEAIABDAGwAbwB1AGQAIABFAGwAYQBzAHQAaQBjACAAQgBsAG8AYwBrACAAUwB0AG8AcgBhAGcAZQAgADIAegBlAGgAeQBqAHQAawB3AGIAOAB1ADIAdQBvAGQANwA0AGcAaQAgADEAAAACAQwA0EEDCgAAAAABAQYAAAMDFxAAAQAAAAAAAAAAAAAAf/8EAE6sCIERn1lNhQ7iGlIsWbI=",
          "variable_data_length": 188,
          "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "de5acbefac0dea7c883e4e2f900cf5a220acdbb443f3982bc0f5d5f80f4eda2470b4db97ddaaba097098248457911e4a"
          }
        ],
        "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAvAAAAAAAAABCAG8AbwB0ADAAMAAwADMAAQAAACYAVQBFAEYASQAgAEEAbABpAGIAYQBiAGEAIABDAGwAbwB1AGQAIABFAGwAYQBzAHQAaQBjACAAQgBsAG8AYwBrACAAUwB0AG8AcgBhAGcAZQAgADIAegBlAGgAeQBqAHQAawB3AGIAOAB1ADIAdQBvAGQANwA0AGcAaQAgADEAAAACAQwA0EEDCgAAAAABAQYAAAMDFxAAAQAAAAAAAAAAAAAAf/8EAE6sCIERn1lNhQ7iGlIsWbI=",
        "index": 2,
        "type_name": "EV_EFI_VARIABLE_BOOT"
      },
      {
        "details": {
          "unicode_name": "Boot0004",
          "unicode_name_length": 8,
          "variable_data": "AQAAACwARQBGAEkAIABJAG4AdABlAHIAbgBhAGwAIABTAGgAZQBsAGwAAAAEBxQAyb24fOv4NE+q6j7kr2UWoQQGFACDpQR8Pp4cT61l4FJo0LTRf/8EAA==",
          "variable_data_length": 88,
          "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "f0fb2cdcc47bf204b41a858f6878b5809c3a9bf6acbd5c4a130f666937a710070c5cf959d3b59c8007b6e63018097d9a"
          }
        ],
        "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAWAAAAAAAAABCAG8AbwB0ADAAMAAwADQAAQAAACwARQBGAEkAIABJAG4AdABlAHIAbgBhAGwAIABTAGgAZQBsAGwAAAAEBxQAyb24fOv4NE+q6j7kr2UWoQQGFACDpQR8Pp4cT61l4FJo0LTRf/8EAA==",
        "index": 2,
        "type_name": "EV_EFI_VARIABLE_BOOT"
      },
      {
        "details": {
          "string": "Calling EFI Application from Boot Option"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71"
          }
        ],
        "event": "Q2FsbGluZyBFRkkgQXBwbGljYXRpb24gZnJvbSBCb290IE9wdGlvbg==",
        "index": 2,
        "type_name": "EV_EFI_ACTION"
      },
      {
        "details": {},
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0"
          }
        ],
        "event": "AAAAAA==",
        "index": 2,
        "type_name": "EV_SEPARATOR"
      },
      {
        "details": {
          "string": "Returning from EFI Application from Boot Option"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "31fddb567dadf4b80770255fa9fde526a6d33dfae40693baf1cb3f8840458e27b60fec855775ec516e6585260d772281"
          }
        ],
        "event": "UmV0dXJuaW5nIGZyb20gRUZJIEFwcGxpY2F0aW9uIGZyb20gQm9vdCBPcHRpb24=",
        "index": 2,
        "type_name": "EV_EFI_ACTION"
      },
      {
        "details": {
          "string": "Calling EFI Application from Boot Option"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71"
          }
        ],
        "event": "Q2FsbGluZyBFRkkgQXBwbGljYXRpb24gZnJvbSBCb290IE9wdGlvbg==",
        "index": 2,
        "type_name": "EV_EFI_ACTION"
      },
      {
        "details": {
          "string": "Returning from EFI Application from Boot Option"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "31fddb567dadf4b80770255fa9fde526a6d33dfae40693baf1cb3f8840458e27b60fec855775ec516e6585260d772281"
          }
        ],
        "event": "UmV0dXJuaW5nIGZyb20gRUZJIEFwcGxpY2F0aW9uIGZyb20gQm9vdCBPcHRpb24=",
        "index": 2,
        "type_name": "EV_EFI_ACTION"
      },
      {
        "details": {
          "string": "Calling EFI Application from Boot Option"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71"
          }
        ],
        "event": "Q2FsbGluZyBFRkkgQXBwbGljYXRpb24gZnJvbSBCb290IE9wdGlvbg==",
        "index": 2,
        "type_name": "EV_EFI_ACTION"
      },
      {
        "details": {},
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "ad03a965ae95d74083436777814522ff3d90ab42005f472ad227af5631252ca0f3d5016c764232a6e523f8ee4bd62003"
          }
        ],
        "event": "RUZJIFBBUlQAAAEAXAAAAK4LlAoAAAAAAQAAAAAAAAD//38CAAAAACIAAAAAAAAA3v9/AgAAAABzSBI2yKTvRrQ2/+SMsn7+AgAAAAAAAACAAAAAgAAAAMlsHbADAAAAAAAAAEhhaCFJZG9udE5lZWRFRknzlXEAgo3EQ5ZvSAaJEHfPAAgAAAAAAAD/FwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKHMqwR/40hG6SwCgyT7JO+EDNkVIHqROjF8xxSty+p8AGAAAAAAAAP9XBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACvPcYPg4RyR455PWnYR33koH9c1nlo+EKJhxUEZzH0VQBYBgAAAAAA//d/AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        "index": 2,
        "type_name": "EV_EFI_GPT_EVENT"
      },
      {
        "details": {
          "device_paths": [
            "ACPI(PNP0A03,0)",
            "Pci(0,3)",
            "Path(3,23,010000000000000000000000)",
            "HD(2,GPT,453603E1-1E48-4EA4-8C5F-31C52B72FA9F,0x1800,0x64000)",
            "File(\\EFI\\BOOT\\BOOTX64.EFI)"
          ]
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "06647f7cd6b1f00433713e895077c986641bfb6bdd3de989575b4fdc34fe557f26990c414158c772393a27732f959dc5"
          }
        ],
        "event": "GGCxuQAAAADwlA4AAAAAAAAAAAAAAAAAgAAAAAAAAAACAQwA0EEDCgAAAAABAQYAAAMDFxAAAQAAAAAAAAAAAAAABAEqAAIAAAAAGAAAAAAAAABABgAAAAAA4QM2RUgepE6MXzHFK3L6nwICBAQwAFwARQBGAEkAXABCAE8ATwBUAFwAQgBPAE8AVABYADYANAAuAEUARgBJAAAAf/8EAA==",
        "index": 2,
        "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION"
      },
      {
        "details": {
          "string": "MokList"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "4793c2425df6a882daddd56a80a155a293a2271977680c51d8a0c0bcc9a7d45121ed4e70aac92a840b80c3a479a156b2"
          }
        ],
        "event": "TW9rTGlzdAA=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "MokListX"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "80ee2571334a57bf90238d21964447e542079d4805fa87887817a97dcb720906683a09b1ac634c76c0c0be1177f76110"
          }
        ],
        "event": "TW9rTGlzdFgA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "unicode_name": "SbatLevel",
          "unicode_name_length": 9,
          "variable_data": "c2JhdCwxLDIwMjEwMzAyMTgK",
          "variable_data_length": 18,
          "variable_name": "50ab5d60-46e0-0043-abb6-3dd810dd8b23"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "f143e2948d63fcd3442e841bb36a7e180871f0a8946541961fe9d12e70d0727874600956264dba531e2edd8729c5eb38"
          }
        ],
        "event": "UKtdYEbgAEOrtj3YEN2LIwkAAAAAAAAAEgAAAAAAAABTAGIAYQB0AEwAZQB2AGUAbABzYmF0LDEsMjAyMTAzMDIxOAo=",
        "index": 1,
        "type_name": "EV_EFI_VARIABLE_AUTHORITY"
      },
      {
        "details": {
          "string": "MokListTrusted"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "8d2ce87d86f55fcfab770a047b090da23270fa206832dfea7e0c946fff451f819add242374be551b0d6318ed6c7d41d8"
          }
        ],
        "event": "TW9rTGlzdFRydXN0ZWQA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "device_paths": [
            "File(\\EFI\\BOOT\\fbx64.efi)"
          ]
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "bce2bd90d09725e13517400431bddad3e71e5ba23ca9589637aae14b9f47bc03f5a443f7a3cf4032897549caf8da356c"
          }
        ],
        "event": "GEDkuQAAAAA4ZQEAAAAAAAAAAAAAAAAAMAAAAAAAAAAEBCwAXABFAEYASQBcAEIATwBPAFQAXABmAGIAeAA2ADQALgBlAGYAaQAAAH//BAA=",
        "index": 2,
        "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION"
      },
      {
        "details": {
          "device_paths": [
            "ACPI(PNP0A03,0)",
            "Pci(0,3)",
            "Path(3,23,010000000000000000000000)",
            "HD(2,GPT,453603E1-1E48-4EA4-8C5F-31C52B72FA9F,0x1800,0x64000)",
            "File(\\EFI\\alinux\\shimx64.efi)"
          ]
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "06647f7cd6b1f00433713e895077c986641bfb6bdd3de989575b4fdc34fe557f26990c414158c772393a27732f959dc5"
          }
        ],
        "event": "GGCxuQAAAADwlA4AAAAAAAAAAAAAAAAAhAAAAAAAAAACAQwA0EEDCgAAAAABAQYAAAMDFxAAAQAAAAAAAAAAAAAABAEqAAIAAAAAGAAAAAAAAABABgAAAAAA4QM2RUgepE6MXzHFK3L6nwICBAQ0AFwARQBGAEkAXABhAGwAaQBuAHUAeABcAHMAaABpAG0AeAA2ADQALgBlAGYAaQAAAH//BAA=",
        "index": 2,
        "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION"
      },
      {
        "details": {
          "string": "MokList"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "4793c2425df6a882daddd56a80a155a293a2271977680c51d8a0c0bcc9a7d45121ed4e70aac92a840b80c3a479a156b2"
          }
        ],
        "event": "TW9rTGlzdAA=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "MokListX"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "80ee2571334a57bf90238d21964447e542079d4805fa87887817a97dcb720906683a09b1ac634c76c0c0be1177f76110"
          }
        ],
        "event": "TW9rTGlzdFgA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "unicode_name": "SbatLevel",
          "unicode_name_length": 9,
          "variable_data": "c2JhdCwxLDIwMjEwMzAyMTgK",
          "variable_data_length": 18,
          "variable_name": "50ab5d60-46e0-0043-abb6-3dd810dd8b23"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "f143e2948d63fcd3442e841bb36a7e180871f0a8946541961fe9d12e70d0727874600956264dba531e2edd8729c5eb38"
          }
        ],
        "event": "UKtdYEbgAEOrtj3YEN2LIwkAAAAAAAAAEgAAAAAAAABTAGIAYQB0AEwAZQB2AGUAbABzYmF0LDEsMjAyMTAzMDIxOAo=",
        "index": 1,
        "type_name": "EV_EFI_VARIABLE_AUTHORITY"
      },
      {
        "details": {
          "string": "MokListTrusted"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "8d2ce87d86f55fcfab770a047b090da23270fa206832dfea7e0c946fff451f819add242374be551b0d6318ed6c7d41d8"
          }
        ],
        "event": "TW9rTGlzdFRydXN0ZWQA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "device_paths": [
            "File(\\EFI\\alinux\\grubx64.efi)"
          ]
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "1c6b41cc5f1e08dff906e381580dc5c200b3c4785f3910682c74fd2ac0421f324216165478595b5e799d2b2134d22b75"
          }
        ],
        "event": "GNB0uQAAAADw5yEAAAAAAAAAAAAAAAAAOAAAAAAAAAAEBDQAXABFAEYASQBcAGEAbABpAG4AdQB4AFwAZwByAHUAYgB4ADYANAAuAGUAZgBpAAAAf/8EAA==",
        "index": 2,
        "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION"
      },
      {
        "details": {
          "string": "grub_cmd search --no-floppy --set prefix --file /boot/grub2/grub.cfg"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "ef1926e0e9144a99eb04fcff8e07cafc952e73cbdfbba52b00d0c385f5026033876653e42afb6a029234315bfc54848f"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2VhcmNoIC0tbm8tZmxvcHB5IC0tc2V0IHByZWZpeCAtLWZpbGUgL2Jvb3QvZ3J1YjIvZ3J1Yi5jZmcAAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set prefix=(hd0,gpt3)/boot/grub2"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "65c0b7e1766391541d7d260263c54a677f7fe29e3b374e1f8b73bdcad86d18d8b531d4c34e0e13166bf67ad4c050c1bb"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IHByZWZpeD0oaGQwLGdwdDMpL2Jvb3QvZ3J1YjIAAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd configfile (hd0,gpt3)/boot/grub2/grub.cfg"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "7be7fe42cdd1f8d81f8f506835fe4cf48feb44fb0701811cc2df4a37048a85fa400d073a90f01ee81bfa4b322a29c1e4"
          }
        ],
        "event": "Z3J1Yl9jbWQgY29uZmlnZmlsZSAoaGQwLGdwdDMpL2Jvb3QvZ3J1YjIvZ3J1Yi5jZmcAAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set pager=1"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "541610ba1bed91de4f8c36d97ec689d7497ef6c243187c3f3fd1e1ba6add24654dd4dd768419b04e4ef354607d4f78a7"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IHBhZ2VyPTEAAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ -f (hd0,gpt3)/boot/grub2/grubenv ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "83bf7ae275fd73b5b61053b6f18827169cb676fb4558489b5b1789b75bbe68774dc66ae2540d0253d56a503334029e01"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAtZiAoaGQwLGdwdDMpL2Jvb3QvZ3J1YjIvZ3J1YmVudiBdAAA=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd load_env -f (hd0,gpt3)/boot/grub2/grubenv"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "53957e3cd72be9a13cfbebee95677833d1998f5cddc183e162f656265276a0ba6822b5820cb21d093347ba79d47262d5"
          }
        ],
        "event": "Z3J1Yl9jbWQgbG9hZF9lbnYgLWYgKGhkMCxncHQzKS9ib290L2dydWIyL2dydWJlbnYAAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [  ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "ed6c2151b8752cebfcc22c918c46d145b2bcadc7ab2613375075ac2d710d99569fad1b72afe4d39d514b26902e6acc47"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAgXQBg",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set default=289800cb8b604e6ba20ec84f5d4e1081-5.10.134-19.1.al8.x86_64"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "377b157430f9aecde64811c9094f10147e27efc1a48b15805641ef87437c106a866839580e24a913d17e7b6adc7b90e3"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IGRlZmF1bHQ9Mjg5ODAwY2I4YjYwNGU2YmEyMGVjODRmNWQ0ZTEwODEtNS4xMC4xMzQtMTkuMS5hbDgueDg2XzY0AAA=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ xy = xy ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "abfd87916395ba336c8493c6609014c188eb8ae02bad29420f43063053511e1b853d73b2c2fc5ff1ad6c6a9df9efac63"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyB4eSA9IHh5IF0AAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd menuentry_id_option=--id"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "a3551c6a27b846cd634f6d2a67d1c0f7ea39d752a5988c209555418267d9445336207edfabe8e7d589cb312f122cf22d"
          }
        ],
        "event": "Z3J1Yl9jbWQgbWVudWVudHJ5X2lkX29wdGlvbj0tLWlkAHU=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd export menuentry_id_option"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "6cbdaeef168b42d6332b4cdb73e8cd06f99ae41296618f7213bfab7cec309ea341bda3a89ba7b989517fc90b7df63b19"
          }
        ],
        "event": "Z3J1Yl9jbWQgZXhwb3J0IG1lbnVlbnRyeV9pZF9vcHRpb24AAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [  ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "ed6c2151b8752cebfcc22c918c46d145b2bcadc7ab2613375075ac2d710d99569fad1b72afe4d39d514b26902e6acc47"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAgXQBA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd terminal_output console"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "929cdbc65d3cbe2f88c73e5aa87627edc48694257ff04a60be6799b6d35acfe535b9e7e8752ebc40909d2dc9871541fa"
          }
        ],
        "event": "Z3J1Yl9jbWQgdGVybWluYWxfb3V0cHV0IGNvbnNvbGUAcg==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ xy = xy ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "abfd87916395ba336c8493c6609014c188eb8ae02bad29420f43063053511e1b853d73b2c2fc5ff1ad6c6a9df9efac63"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyB4eSA9IHh5IF0AcA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set timeout_style=menu"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "9050f208cac2b78d1ff0fad5f8e59b5869beabc2129b7bd17b5b16f0d28c929704a70630060ea4acf968f15ad226daa4"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IHRpbWVvdXRfc3R5bGU9bWVudQAA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set timeout=1"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "c1328422f4aa28832e7bbbcdf9ce3d09841f34d3f5079fa0d412b2212d68bb5a7676718f077fcc4eb41381cc6f2884f7"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IHRpbWVvdXQ9MQB0",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set tuned_params="
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "e7398a8d0b8c3656d53b8173b6844a193dc79f76072c157fae7e76cdd63b9396a0cde2897f6d1c0f5c2765c95b4fe26a"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IHR1bmVkX3BhcmFtcz0Abg==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set tuned_initrd="
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "3a74cde705411602dcf2350d8cda85954eb9cc2fe74f39d0aa0a9d4d42d121a4b81227cf6b26d0e4c0e6fa1e5d0ede46"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IHR1bmVkX2luaXRyZD0AYA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ -f (hd0,gpt3)/boot/grub2/user.cfg ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "ecf8f05c07942142a04344af5b73bfc70d3de06f4cf4e78882038dde4ca7ebecec6fb93404c01fd31c2fced20f135e91"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAtZiAoaGQwLGdwdDMpL2Jvb3QvZ3J1YjIvdXNlci5jZmcgXQAg",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd insmod increment"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "f6e32f8a184ac29e78be95a10d8ce9206318645ae6c5e7a9a753c94c1f8e1fa409ab318ca8d0fdb18091d91305ed07a2"
          }
        ],
        "event": "Z3J1Yl9jbWQgaW5zbW9kIGluY3JlbWVudAAA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ -n  -a 0 = 0 ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "765405cb564cfdbad5cd346e6ef6a57e7c7a82b594f7e31e055b2b119c78747f37795487332e0c6a7a4718cfae6d600c"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAtbiAgLWEgMCA9IDAgXQAA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd insmod part_gpt"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "1bd9a5b86c57cd269dde4e10ca5c6c514cc06735a532c4036b7c2e9251632d28aa3bdaab2f2f9d0dccf6c6dca23aacd4"
          }
        ],
        "event": "Z3J1Yl9jbWQgaW5zbW9kIHBhcnRfZ3B0AH8=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd insmod ext2"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "44adf16d5b9fb7e2fdae89adbe097c246baa5bd35ea09026cdf9c990b21a1716e03ae357e8f094650ac7b4e23526d934"
          }
        ],
        "event": "Z3J1Yl9jbWQgaW5zbW9kIGV4dDIAAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set root=hd0,gpt3"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "271e7443500957853c2d482b4fc9585435e3e2dec1b6ac190e87e9ffd7db4dd25cbfa919e7e2c2322557f564ffe872f2"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IHJvb3Q9aGQwLGdwdDMAAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ xy = xy ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "abfd87916395ba336c8493c6609014c188eb8ae02bad29420f43063053511e1b853d73b2c2fc5ff1ad6c6a9df9efac63"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyB4eSA9IHh5IF0AAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd search --no-floppy --fs-uuid --set=root --hint=hd0,gpt3 33b46ac5-7482-4aa5-8de0-60ab4c3a4c78"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "49fdcf213de1ee7b3135699e7964d88678a13caf7edb7614844db7c3298af95227e17fc24c234c21a588dc047415f149"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2VhcmNoIC0tbm8tZmxvcHB5IC0tZnMtdXVpZCAtLXNldD1yb290IC0taGludD1oZDAsZ3B0MyAzM2I0NmFjNS03NDgyLTRhYTUtOGRlMC02MGFiNGMzYTRjNzgAiw==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd insmod part_gpt"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "1bd9a5b86c57cd269dde4e10ca5c6c514cc06735a532c4036b7c2e9251632d28aa3bdaab2f2f9d0dccf6c6dca23aacd4"
          }
        ],
        "event": "Z3J1Yl9jbWQgaW5zbW9kIHBhcnRfZ3B0AAA=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd insmod ext2"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "44adf16d5b9fb7e2fdae89adbe097c246baa5bd35ea09026cdf9c990b21a1716e03ae357e8f094650ac7b4e23526d934"
          }
        ],
        "event": "Z3J1Yl9jbWQgaW5zbW9kIGV4dDIAZw==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set boot=hd0,gpt3"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "bd4e0db9d3a5576ed04669ba693b37209885329af0c7845b111f245a8d4dcdab98f82bc9cffc22bd0d5d881dca6d5b73"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IGJvb3Q9aGQwLGdwdDMAAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ xy = xy ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "abfd87916395ba336c8493c6609014c188eb8ae02bad29420f43063053511e1b853d73b2c2fc5ff1ad6c6a9df9efac63"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyB4eSA9IHh5IF0AAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd search --no-floppy --fs-uuid --set=boot --hint=hd0,gpt3 33b46ac5-7482-4aa5-8de0-60ab4c3a4c78"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "bf468b66e52dbba9488e61693ecc24f2b8b96109f14892de5436ba5f0fca7c14b30e8b53f78a09c57381101098c14fa5"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2VhcmNoIC0tbm8tZmxvcHB5IC0tZnMtdXVpZCAtLXNldD1ib290IC0taGludD1oZDAsZ3B0MyAzM2I0NmFjNS03NDgyLTRhYTUtOGRlMC02MGFiNGMzYTRjNzgA5g==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ -z root=UUID=33b46ac5-7482-4aa5-8de0-60ab4c3a4c78 ro  rhgb quiet cgroup.memory=nokmem crashkernel=0M-2G:0M,2G-8G:192M,8G-128G:256M,128G-376G:384M,376G-:448M spec_rstack_overflow=off vring_force_dma_api kfence.sample_interval=100 kfence.booting_max=0-2G:0,2G-32G:2M,32G-:32M preempt=none biosdevname=0 net.ifnames=0 console=tty0 console=ttyS0,115200n8 noibrs nvme_core.io_timeout=4294967295 nvme_core.admin_timeout=4294967295 cryptomgr.notests rcupdate.rcu_cpu_stall_timeout=300  ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "f2895b17e40c708675e4d4292144e46dff4025f21949c6050f109d52fc195157a6a05c10a0a8d3de1cff6bbbe98fe760"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAteiByb290PVVVSUQ9MzNiNDZhYzUtNzQ4Mi00YWE1LThkZTAtNjBhYjRjM2E0Yzc4IHJvICByaGdiIHF1aWV0IGNncm91cC5tZW1vcnk9bm9rbWVtIGNyYXNoa2VybmVsPTBNLTJHOjBNLDJHLThHOjE5Mk0sOEctMTI4RzoyNTZNLDEyOEctMzc2RzozODRNLDM3NkctOjQ0OE0gc3BlY19yc3RhY2tfb3ZlcmZsb3c9b2ZmIHZyaW5nX2ZvcmNlX2RtYV9hcGkga2ZlbmNlLnNhbXBsZV9pbnRlcnZhbD0xMDAga2ZlbmNlLmJvb3RpbmdfbWF4PTAtMkc6MCwyRy0zMkc6Mk0sMzJHLTozMk0gcHJlZW1wdD1ub25lIGJpb3NkZXZuYW1lPTAgbmV0LmlmbmFtZXM9MCBjb25zb2xlPXR0eTAgY29uc29sZT10dHlTMCwxMTUyMDBuOCBub2licnMgbnZtZV9jb3JlLmlvX3RpbWVvdXQ9NDI5NDk2NzI5NSBudm1lX2NvcmUuYWRtaW5fdGltZW91dD00Mjk0OTY3Mjk1IGNyeXB0b21nci5ub3Rlc3RzIHJjdXBkYXRlLnJjdV9jcHVfc3RhbGxfdGltZW91dD0zMDAgIF0AsA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd insmod blscfg"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "20e74f04f6c6690600634d1071b2d0c7df6b1d20cffd8ed916f4a391a7872f68e8299127442bdd51617674b04998666d"
          }
        ],
        "event": "Z3J1Yl9jbWQgaW5zbW9kIGJsc2NmZwBH",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd blscfg"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "134200ae62ba8c93d6ddf14bb15161067c1f3882d166ccb9077d698443fc4ade8bcbd9f69a3deb02cc652d540ea3a99f"
          }
        ],
        "event": "Z3J1Yl9jbWQgYmxzY2ZnAHU=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ 0 = 1 -o  = 1 ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "c0ce14ffa31741acdf895a752f3450a38b2072e22e773f05508fb33e9cf0138907dde4f724cb3ddb2a128a96eed470cf"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAwID0gMSAtbyAgPSAxIF0AAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set menu_hide_ok=0"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "cd81327d6b6b3d0cd70dda916c12f8df02ddf1f251d53721f60a20d8bc8821c48b209bdccc44ffe645193d2cc85dfc3a"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IG1lbnVfaGlkZV9vaz0wAAA=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ 0 = 1 ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "4c09d89df2f1fc4144192fce1ed0d499ee8a825c195710fd1f6cfce2b78d447696ae976f02065785da54660818a341a0"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAwID0gMSBdAAA=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [  = 1 ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "9232e2efad224807177491aa665b60c5a9905aba0119fdfe43f87f0a87147c6d0495b2412870f5d2124a5fdf16f1b8d6"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAgPSAxIF0AAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set boot_success=0"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "4c8ffd4bb6067d7d288b4b19d6c496d036468bb6f1139d0ba47a7b62572b85cf31d922666e4c7975137ea36721c50016"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IGJvb3Rfc3VjY2Vzcz0wAAA=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd save_env boot_success boot_indeterminate"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "19a9c0cdc635cd16f5e2b6f7f14f8f6114f987ca8fa466c22a9e1baa4cc0b19f344135debde1400e6a2a5ed236a37ab5"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2F2ZV9lbnYgYm9vdF9zdWNjZXNzIGJvb3RfaW5kZXRlcm1pbmF0ZQAA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ xy = xy ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "abfd87916395ba336c8493c6609014c188eb8ae02bad29420f43063053511e1b853d73b2c2fc5ff1ad6c6a9df9efac63"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyB4eSA9IHh5IF0AAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [  ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "ed6c2151b8752cebfcc22c918c46d145b2bcadc7ab2613375075ac2d710d99569fad1b72afe4d39d514b26902e6acc47"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAgXQAA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [  -a 0 = 1 ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "155edd9112a5e28266fe6124e201b4a305bce899a94cc2b55a014641b06f911b8a0b50d96d64852c0aa159665341e719"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAgLWEgMCA9IDEgXQAA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ -f (hd0,gpt3)/boot/grub2/custom.cfg ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "a1480dea11d385409f75069533a69a4129186f226737b4df52ea422c40aca25e3af3f68129d730b8dabdc6bd5a91cd3a"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAtZiAoaGQwLGdwdDMpL2Jvb3QvZ3J1YjIvY3VzdG9tLmNmZyBdAL4=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ -z (hd0,gpt3)/boot/grub2 -a -f (hd0,gpt3)/boot/grub2/custom.cfg ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "f2838546cf77361db1f80e60193f57e9863513318ae75bdcdaacfd13f4288628fb78136dfab3509d0cfe4da5311c8e50"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyAteiAoaGQwLGdwdDMpL2Jvb3QvZ3J1YjIgLWEgLWYgKGhkMCxncHQzKS9ib290L2dydWIyL2N1c3RvbS5jZmcgXQAA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd load_video"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "aa7a659b9b166fa2a50936ffcf937984828a7ccb864239d6c73683ee216088ac103f0988e668293a140ba7f5049ebb17"
          }
        ],
        "event": "Z3J1Yl9jbWQgbG9hZF92aWRlbwAA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd [ xy = xy ]"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "abfd87916395ba336c8493c6609014c188eb8ae02bad29420f43063053511e1b853d73b2c2fc5ff1ad6c6a9df9efac63"
          }
        ],
        "event": "Z3J1Yl9jbWQgWyB4eSA9IHh5IF0AAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd insmod all_video"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "d3f2edb62f6e652681db7dd3ca50d98e6755c1336bc99c70fae4486215bdc2665e0aa6d8728fa1e37a5befecac7d6354"
          }
        ],
        "event": "Z3J1Yl9jbWQgaW5zbW9kIGFsbF92aWRlbwAA",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd set gfx_payload=keep"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "99d55f94c0d9e8c9f2a570b2543f449f67d78e8e35222920ab305d438d6e1f7e0ba2424497f617fe74adaefa2f1ff685"
          }
        ],
        "event": "Z3J1Yl9jbWQgc2V0IGdmeF9wYXlsb2FkPWtlZXAAAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd insmod gzio"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "af8eab8c8a4ce406f93153ad019b061ab90b75185ee4061c43dfaf75d668ad97b6cfa3d41e77d15652b6be8a13f78b9f"
          }
        ],
        "event": "Z3J1Yl9jbWQgaW5zbW9kIGd6aW8AAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd linux (hd0,gpt3)/boot/vmlinuz-5.10.134-19.1.al8.x86_64 root=UUID=33b46ac5-7482-4aa5-8de0-60ab4c3a4c78 ro rhgb quiet cgroup.memory=nokmem crashkernel=0M-2G:0M,2G-8G:192M,8G-128G:256M,128G-376G:384M,376G-:448M spec_rstack_overflow=off vring_force_dma_api kfence.sample_interval=100 kfence.booting_max=0-2G:0,2G-32G:2M,32G-:32M preempt=none biosdevname=0 net.ifnames=0 console=tty0 console=ttyS0,115200n8 noibrs nvme_core.io_timeout=4294967295 nvme_core.admin_timeout=4294967295 cryptomgr.notests rcupdate.rcu_cpu_stall_timeout=300"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "f94d08196dfced4459960f3bbe5b5241058af31e2fe4d49aa42547ec4ece920fbfec8a80adddcf5a767c677311e71fa6"
          }
        ],
        "event": "Z3J1Yl9jbWQgbGludXggKGhkMCxncHQzKS9ib290L3ZtbGludXotNS4xMC4xMzQtMTkuMS5hbDgueDg2XzY0IHJvb3Q9VVVJRD0zM2I0NmFjNS03NDgyLTRhYTUtOGRlMC02MGFiNGMzYTRjNzggcm8gcmhnYiBxdWlldCBjZ3JvdXAubWVtb3J5PW5va21lbSBjcmFzaGtlcm5lbD0wTS0yRzowTSwyRy04RzoxOTJNLDhHLTEyOEc6MjU2TSwxMjhHLTM3Nkc6Mzg0TSwzNzZHLTo0NDhNIHNwZWNfcnN0YWNrX292ZXJmbG93PW9mZiB2cmluZ19mb3JjZV9kbWFfYXBpIGtmZW5jZS5zYW1wbGVfaW50ZXJ2YWw9MTAwIGtmZW5jZS5ib290aW5nX21heD0wLTJHOjAsMkctMzJHOjJNLDMyRy06MzJNIHByZWVtcHQ9bm9uZSBiaW9zZGV2bmFtZT0wIG5ldC5pZm5hbWVzPTAgY29uc29sZT10dHkwIGNvbnNvbGU9dHR5UzAsMTE1MjAwbjggbm9pYnJzIG52bWVfY29yZS5pb190aW1lb3V0PTQyOTQ5NjcyOTUgbnZtZV9jb3JlLmFkbWluX3RpbWVvdXQ9NDI5NDk2NzI5NSBjcnlwdG9tZ3Iubm90ZXN0cyByY3VwZGF0ZS5yY3VfY3B1X3N0YWxsX3RpbWVvdXQ9MzAwAG4=",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_linuxefi Kernel"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "7ecde58258fb08dfd147cfdba2443ecfeae8b97fed8efe0cee199cd71dcc2fb7ff3d23e7ebcb24965186524c9904b84c"
          }
        ],
        "event": "Z3J1Yl9saW51eGVmaSBLZXJuZWwAbA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_kernel_cmdline (hd0,gpt3)/boot/vmlinuz-5.10.134-19.1.al8.x86_64 root=UUID=33b46ac5-7482-4aa5-8de0-60ab4c3a4c78 ro rhgb quiet cgroup.memory=nokmem crashkernel=0M-2G:0M,2G-8G:192M,8G-128G:256M,128G-376G:384M,376G-:448M spec_rstack_overflow=off vring_force_dma_api kfence.sample_interval=100 kfence.booting_max=0-2G:0,2G-32G:2M,32G-:32M preempt=none biosdevname=0 net.ifnames=0 console=tty0 console=ttyS0,115200n8 noibrs nvme_core.io_timeout=4294967295 nvme_core.admin_timeout=4294967295 cryptomgr.notests rcupdate.rcu_cpu_stall_timeout=300"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "6a3d314eb16073a6c426173723c0a57a1e5c4efe9b355730d2c80be1026f8d03493355c5077c81f69fa05571406b96f8"
          }
        ],
        "event": "Z3J1Yl9rZXJuZWxfY21kbGluZSAoaGQwLGdwdDMpL2Jvb3Qvdm1saW51ei01LjEwLjEzNC0xOS4xLmFsOC54ODZfNjQgcm9vdD1VVUlEPTMzYjQ2YWM1LTc0ODItNGFhNS04ZGUwLTYwYWI0YzNhNGM3OCBybyByaGdiIHF1aWV0IGNncm91cC5tZW1vcnk9bm9rbWVtIGNyYXNoa2VybmVsPTBNLTJHOjBNLDJHLThHOjE5Mk0sOEctMTI4RzoyNTZNLDEyOEctMzc2RzozODRNLDM3NkctOjQ0OE0gc3BlY19yc3RhY2tfb3ZlcmZsb3c9b2ZmIHZyaW5nX2ZvcmNlX2RtYV9hcGkga2ZlbmNlLnNhbXBsZV9pbnRlcnZhbD0xMDAga2ZlbmNlLmJvb3RpbmdfbWF4PTAtMkc6MCwyRy0zMkc6Mk0sMzJHLTozMk0gcHJlZW1wdD1ub25lIGJpb3NkZXZuYW1lPTAgbmV0LmlmbmFtZXM9MCBjb25zb2xlPXR0eTAgY29uc29sZT10dHlTMCwxMTUyMDBuOCBub2licnMgbnZtZV9jb3JlLmlvX3RpbWVvdXQ9NDI5NDk2NzI5NSBudm1lX2NvcmUuYWRtaW5fdGltZW91dD00Mjk0OTY3Mjk1IGNyeXB0b21nci5ub3Rlc3RzIHJjdXBkYXRlLnJjdV9jcHVfc3RhbGxfdGltZW91dD0zMDAAXw==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_cmd initrd (hd0,gpt3)/boot/initramfs-5.10.134-19.1.al8.x86_64.img"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "b6de3f0fdc20f7cd81c3708d9cf2974b3b574d842e98a8b953266e0a65c1b1fe6acd95e2ab54f617b32d8cd5c4ee2fb6"
          }
        ],
        "event": "Z3J1Yl9jbWQgaW5pdHJkIChoZDAsZ3B0MykvYm9vdC9pbml0cmFtZnMtNS4xMC4xMzQtMTkuMS5hbDgueDg2XzY0LmltZwA2",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "grub_linuxefi Initrd"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "7de50181f02be7ff689b04a54d2ee3ac78cb5ac3fbc9e07bac7d0e75c27c21ee7d40cc3500dfe2fa17036567273cd777"
          }
        ],
        "event": "Z3J1Yl9saW51eGVmaSBJbml0cmQAAA==",
        "index": 3,
        "type_name": "EV_IPL"
      },
      {
        "details": {
          "string": "Exit Boot Services Invocation"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "214b0bef1379756011344877743fdc2a5382bac6e70362d624ccf3f654407c1b4badf7d8f9295dd3dabdef65b27677e0"
          }
        ],
        "event": "RXhpdCBCb290IFNlcnZpY2VzIEludm9jYXRpb24=",
        "index": 2,
        "type_name": "EV_EFI_ACTION"
      },
      {
        "details": {
          "string": "Exit Boot Services Returned with Success"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "0a2e01c85deae718a530ad8c6d20a84009babe6c8989269e950d8cf440c6e997695e64d455c4174a652cd080f6230b74"
          }
        ],
        "event": "RXhpdCBCb290IFNlcnZpY2VzIFJldHVybmVkIHdpdGggU3VjY2Vzcw==",
        "index": 2,
        "type_name": "EV_EFI_ACTION"
      },
      {
        "details": {
          "data": {
            "content": "39f62a1114b8104fc23bd252b83aca32b492ece583be5b824303f2f90df851e8",
            "domain": "file",
            "operation": "/usr/local/bin/attestation-agent"
          },
          "string": "file /usr/local/bin/attestation-agent 39f62a1114b8104fc23bd252b83aca32b492ece583be5b824303f2f90df851e8",
          "unicode_name": "AAEL"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "465b59d48076cdd8b5caa6231e337cb8c8d2f8700e4d2c76871cda935bb0e19f3828fc2d81b68a57c24c3a12185e7d1b"
          }
        ],
        "event": "TEVBQWYAAABmaWxlIC91c3IvbG9jYWwvYmluL2F0dGVzdGF0aW9uLWFnZW50IDM5ZjYyYTExMTRiODEwNGZjMjNiZDI1MmI4M2FjYTMyYjQ5MmVjZTU4M2JlNWI4MjQzMDNmMmY5MGRmODUxZTg=",
        "index": 4,
        "type_name": "EV_EVENT_TAG"
      },
      {
        "details": {
          "data": {
            "content": "f627e8ed61f7561d72db764b87d2115e73ff31ac77e54b6e7243055e9e9ce1fe",
            "domain": "file",
            "operation": "/etc/trustiflux/attestation-agent.toml"
          },
          "string": "file /etc/trustiflux/attestation-agent.toml f627e8ed61f7561d72db764b87d2115e73ff31ac77e54b6e7243055e9e9ce1fe",
          "unicode_name": "AAEL"
        },
        "digests": [
          {
            "alg": "SHA-384",
            "digest": "abb9e67af41dc0a43b13fcfda0991e80895d840b231acdfe192dada3df8b72a9440ba92bfd9d68362bec2f8f7ef2949e"
          }
        ],
        "event": "TEVBQWwAAABmaWxlIC9ldGMvdHJ1c3RpZmx1eC9hdHRlc3RhdGlvbi1hZ2VudC50b21sIGY2MjdlOGVkNjFmNzU2MWQ3MmRiNzY0Yjg3ZDIxMTVlNzNmZjMxYWM3N2U1NGI2ZTcyNDMwNTVlOWU5Y2UxZmU=",
        "index": 4,
        "type_name": "EV_EVENT_TAG"
      }
    ]
  }
}
```

## CSV

`submods.cpu0.ear.veraison.annotated-evidence.csv`值：

```json
{
          "build": 2339,
          "measure": "21c36b1e9d407b7ae3c900fd97c212645e29b64949f1a9e55b8e07f875a04b5f",
          "mnonce": "f4b75e18a9b2af97e65ba476347c4802",
          "policy": {
            "api_major": 0,
            "api_minor": 0,
            "asid_reuse": 0,
            "cek_version": 0,
            "csv": 0,
            "csv3": 1,
            "domain": 0,
            "es": 1,
            "hsk_version": 0,
            "nodbg": 1,
            "noks": 0,
            "nosend": 0
          },
          "reserved0": "0000000000000000000000000000",
          "reserved1": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "rtmr0": "21c36b1e9d407b7ae3c900fd97c212645e29b64949f1a9e55b8e07f875a04b5f",
          "rtmr1": "b9a0e7718045b15c45019ad66797dbc7f495bd5cca370f7bd7fabeebca19b4d5",
          "rtmr2": "6242f28e40147a7cf0672008900210125e3bfbfc1e7752dc4575f23efa853fa9",
          "rtmr3": "2b9fcd4d5dfdbb41ef158fe4152d7fd2aaa4c8ea4d58ce72d8f482bf977534b2",
          "rtmr4": "0000000000000000000000000000000000000000000000000000000000000000",
          "rtmr_version": 1,
          "serial_number": "TM8L28A015011001",
          "sig_algo": "04000000",
          "sig_usage": "02100000",
          "uefi_event_logs": [
            {
              "details": {
                "unicode_name": "SecureBoot",
                "unicode_name_length": 10,
                "variable_data": "",
                "variable_data_length": 0,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "b4ca5cb300a44b541cf7978203bc2d769622e695dc18549bd23b8378fcdef522"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAoAAAAAAAAAAAAAAAAAAABTAGUAYwB1AHIAZQBCAG8AbwB0AA==",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG"
            },
            {
              "details": {
                "unicode_name": "PK",
                "unicode_name_length": 2,
                "variable_data": "",
                "variable_data_length": 0,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "205702258aeaecaf68533e90c2c6cb17cdc1bc34f5c99e0564bb57f5ed3a0e27"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAIAAAAAAAAAAAAAAAAAAABQAEsA",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG"
            },
            {
              "details": {
                "unicode_name": "KEK",
                "unicode_name_length": 3,
                "variable_data": "",
                "variable_data_length": 0,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "97f842cf8be3ef0c9b1e5fb6d4ab4af26b2943e5ce349883afdf607e81707f7a"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAMAAAAAAAAAAAAAAAAAAABLAEUASwA=",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG"
            },
            {
              "details": {
                "unicode_name": "db",
                "unicode_name_length": 2,
                "variable_data": "",
                "variable_data_length": 0,
                "variable_name": "cbb219d7-3a3d-9645-a3bc-dad00e67656f"
              },
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "f78247933758602a0e2ba38cdc7efb4b55d4a17f9aec21df6af56d6c7389bb05"
                }
              ],
              "event": "y7IZ1zo9lkWjvNrQDmdlbwIAAAAAAAAAAAAAAAAAAABkAGIA",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG"
            },
            {
              "details": {
                "unicode_name": "dbx",
                "unicode_name_length": 3,
                "variable_data": "",
                "variable_data_length": 0,
                "variable_name": "cbb219d7-3a3d-9645-a3bc-dad00e67656f"
              },
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "e77ef9cdb81c85e0f9b1a19f7859b762b7b6baafbf4a195eca0b868fa20f8df2"
                }
              ],
              "event": "y7IZ1zo9lkWjvNrQDmdlbwMAAAAAAAAAAAAAAAAAAABkAGIAeAA=",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_DRIVER_CONFIG"
            },
            {
              "details": {},
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "afcc870fa20c507995499794371e8c25e3a7310fa72200c109379973ae236845"
                }
              ],
              "event": "AAAAAA==",
              "index": 1,
              "type_name": "EV_SEPARATOR"
            },
            {
              "details": {
                "unicode_name": "BootOrder",
                "unicode_name_length": 9,
                "variable_data": "CAAAAAEAAgADAAQABQAGAAcA",
                "variable_data_length": 18,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "f3380b81161aa412df6b9963d065ab39c83e426e1da460794b271222cbe8aa96"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAkAAAAAAAAAEgAAAAAAAABCAG8AbwB0AE8AcgBkAGUAcgAIAAAAAQACAAMABAAFAAYABwA=",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_BOOT"
            },
            {
              "details": {
                "unicode_name": "Boot0008",
                "unicode_name_length": 8,
                "variable_data": "AQAAAGIAQQBuAG8AbABpAHMAIABPAFMAAAAEASoAAgAAAAAYAAAAAAAAAEAGAAAAAACTj2+hcTAQRK83TfIDsWwqAgIEBDQAXABFAEYASQBcAGEAbgBvAGwAaQBzAFwAcwBoAGkAbQB4ADYANAAuAGUAZgBpAAAAf/8EAA==",
                "variable_data_length": 124,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "25a7b5c4844c85ebe4b19c7bebe76ea5749efcbe88162f76bf00d7b489d4d108"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAfAAAAAAAAABCAG8AbwB0ADAAMAAwADgAAQAAAGIAQQBuAG8AbABpAHMAIABPAFMAAAAEASoAAgAAAAAYAAAAAAAAAEAGAAAAAACTj2+hcTAQRK83TfIDsWwqAgIEBDQAXABFAEYASQBcAGEAbgBvAGwAaQBzAFwAcwBoAGkAbQB4ADYANAAuAGUAZgBpAAAAf/8EAA==",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_BOOT"
            },
            {
              "details": {
                "unicode_name": "Boot0000",
                "unicode_name_length": 8,
                "variable_data": "CQEAACwAVQBpAEEAcABwAAAABAcUAMm9uHzr+DRPquo+5K9lFqEEBhQAIaosRhR2A0WDboq29GYjMX//BAA=",
                "variable_data_length": 62,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "c3116e37611507bb0a8959327527f6c96523c4479070be2b5d0aece22404e784"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAPgAAAAAAAABCAG8AbwB0ADAAMAAwADAACQEAACwAVQBpAEEAcABwAAAABAcUAMm9uHzr+DRPquo+5K9lFqEEBhQAIaosRhR2A0WDboq29GYjMX//BAA=",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_BOOT"
            },
            {
              "details": {
                "unicode_name": "Boot0001",
                "unicode_name_length": 8,
                "variable_data": "AQAAAB4AVQBFAEYASQAgAFEARQBNAFUAIABEAFYARAAtAFIATwBNACAAUQBNADAAMAAwADAAMwAgAAAAAgEMANBBAwoAAAAAAQEGAAEBAwEIAAEAAAB//wQATqwIgRGfWU2FDuIaUixZsg==",
                "variable_data_length": 106,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "caee3833a54b97cca63022b5b88ad18a3f41c2e2724c53b9e0a46e069d13ff6b"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAagAAAAAAAABCAG8AbwB0ADAAMAAwADEAAQAAAB4AVQBFAEYASQAgAFEARQBNAFUAIABEAFYARAAtAFIATwBNACAAUQBNADAAMAAwADAAMwAgAAAAAgEMANBBAwoAAAAAAQEGAAEBAwEIAAEAAAB//wQATqwIgRGfWU2FDuIaUixZsg==",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_BOOT"
            },
            {
              "details": {
                "unicode_name": "Boot0002",
                "unicode_name_length": 8,
                "variable_data": "AQAAAB4AVQBFAEYASQAgAFEARQBNAFUAIABIAEEAUgBEAEQASQBTAEsAIABRAE0AMAAwADAAMAAxACAAAAACAQwA0EEDCgAAAAABAQYAAQEDAQgAAAAAAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
                "variable_data_length": 108,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "3fdfca6616740823d53b09b78caf8911a5d9a8ef90852f17225813dbec71d7d9"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAbAAAAAAAAABCAG8AbwB0ADAAMAAwADIAAQAAAB4AVQBFAEYASQAgAFEARQBNAFUAIABIAEEAUgBEAEQASQBTAEsAIABRAE0AMAAwADAAMAAxACAAAAACAQwA0EEDCgAAAAABAQYAAQEDAQgAAAAAAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_BOOT"
            },
            {
              "details": {
                "unicode_name": "Boot0003",
                "unicode_name_length": 8,
                "variable_data": "AQAAAFYAVQBFAEYASQAgAFAAWABFAHYANAAgACgATQBBAEMAOgA1ADIANQA0ADAAMAAxADIAMwA0ADUANgApAAAAAgEMANBBAwoAAAAAAQEGAAADAwslAFJUABI0VgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMMGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
                "variable_data_length": 168,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "1a475ffdd6693e3e15f44c0a84a4f4d7017a6a5188b6bfe24431d29ccaa63c59"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAqAAAAAAAAABCAG8AbwB0ADAAMAAwADMAAQAAAFYAVQBFAEYASQAgAFAAWABFAHYANAAgACgATQBBAEMAOgA1ADIANQA0ADAAMAAxADIAMwA0ADUANgApAAAAAgEMANBBAwoAAAAAAQEGAAADAwslAFJUABI0VgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMMGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_BOOT"
            },
            {
              "details": {
                "unicode_name": "Boot0004",
                "unicode_name_length": 8,
                "variable_data": "AQAAAHcAVQBFAEYASQAgAFAAWABFAHYANgAgACgATQBBAEMAOgA1ADIANQA0ADAAMAAxADIAMwA0ADUANgApAAAAAgEMANBBAwoAAAAAAQEGAAADAwslAFJUABI0VgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMNPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
                "variable_data_length": 201,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "226fa299aea858090c944ed8d35d035b627353f1d44ace4e99d5b7d6a1226949"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAyQAAAAAAAABCAG8AbwB0ADAAMAAwADQAAQAAAHcAVQBFAEYASQAgAFAAWABFAHYANgAgACgATQBBAEMAOgA1ADIANQA0ADAAMAAxADIAMwA0ADUANgApAAAAAgEMANBBAwoAAAAAAQEGAAADAwslAFJUABI0VgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMNPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_BOOT"
            },
            {
              "details": {
                "unicode_name": "Boot0005",
                "unicode_name_length": 8,
                "variable_data": "AQAAAFoAVQBFAEYASQAgAEgAVABUAFAAdgA0ACAAKABNAEEAQwA6ADUAMgA1ADQAMAAwADEAMgAzADQANQA2ACkAAAACAQwA0EEDCgAAAAABAQYAAAMDCyUAUlQAEjRWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAwwbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxgEAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
                "variable_data_length": 174,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "e5431d01e74fba877bf7c79291b03372e5fbd0f1bda902c8e208b09366b48a08"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAArgAAAAAAAABCAG8AbwB0ADAAMAAwADUAAQAAAFoAVQBFAEYASQAgAEgAVABUAFAAdgA0ACAAKABNAEEAQwA6ADUAMgA1ADQAMAAwADEAMgAzADQANQA2ACkAAAACAQwA0EEDCgAAAAABAQYAAAMDCyUAUlQAEjRWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAwwbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxgEAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_BOOT"
            },
            {
              "details": {
                "unicode_name": "Boot0006",
                "unicode_name_length": 8,
                "variable_data": "AQAAAHsAVQBFAEYASQAgAEgAVABUAFAAdgA2ACAAKABNAEEAQwA6ADUAMgA1ADQAMAAwADEAMgAzADQANQA2ACkAAAACAQwA0EEDCgAAAAABAQYAAAMDCyUAUlQAEjRWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAw08AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAxgEAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
                "variable_data_length": 207,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "5b015e9c8f019c89be7d4dda7e36f952fbb2cad0bffeb07cc6f301eaed3a3922"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAzwAAAAAAAABCAG8AbwB0ADAAMAAwADYAAQAAAHsAVQBFAEYASQAgAEgAVABUAFAAdgA2ACAAKABNAEEAQwA6ADUAMgA1ADQAMAAwADEAMgAzADQANQA2ACkAAAACAQwA0EEDCgAAAAABAQYAAAMDCyUAUlQAEjRWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAw08AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAxgEAH//BABOrAiBEZ9ZTYUO4hpSLFmy",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_BOOT"
            },
            {
              "details": {
                "unicode_name": "Boot0007",
                "unicode_name_length": 8,
                "variable_data": "AQAAACwARQBGAEkAIABJAG4AdABlAHIAbgBhAGwAIABTAGgAZQBsAGwAAAAEBxQAyb24fOv4NE+q6j7kr2UWoQQGFACDpQR8Pp4cT61l4FJo0LTRf/8EAA==",
                "variable_data_length": 88,
                "variable_name": "61dfe48b-ca93-d211-aa0d-00e098032b8c"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "faf30d2e01b7cb766ccaf2c4b001ed8102a34697671834109ac007b70136c260"
                }
              ],
              "event": "Yd/ki8qT0hGqDQDgmAMrjAgAAAAAAAAAWAAAAAAAAABCAG8AbwB0ADAAMAAwADcAAQAAACwARQBGAEkAIABJAG4AdABlAHIAbgBhAGwAIABTAGgAZQBsAGwAAAAEBxQAyb24fOv4NE+q6j7kr2UWoQQGFACDpQR8Pp4cT61l4FJo0LTRf/8EAA==",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_BOOT"
            },
            {
              "details": {
                "string": "Calling EFI Application from Boot Option"
              },
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "0c45a5c3c304d73f1a9d73d4fe03190cf1861e89ba5b958752aba51c6fb5fc5a"
                }
              ],
              "event": "Q2FsbGluZyBFRkkgQXBwbGljYXRpb24gZnJvbSBCb290IE9wdGlvbg==",
              "index": 2,
              "type_name": "EV_EFI_ACTION"
            },
            {
              "details": {},
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "afcc870fa20c507995499794371e8c25e3a7310fa72200c109379973ae236845"
                }
              ],
              "event": "AAAAAA==",
              "index": 2,
              "type_name": "EV_SEPARATOR"
            },
            {
              "details": {},
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "aabd6e20719ef81a851186b7923144b999503b1ca28718f77470e0bd555ee5f6"
                }
              ],
              "event": "RUZJIFBBUlQAAAEAXAAAAG1U3J8AAAAAAQAAAAAAAAD//38CAAAAACIAAAAAAAAA3v9/AgAAAADmzMCqGsewQbXUFkAQvP+lAgAAAAAAAACAAAAAgAAAAJcRUtwDAAAAAAAAAEhhaCFJZG9udE5lZWRFRknfllFGpHw2QqTrpeggOBweAAgAAAAAAAD/FwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKHMqwR/40hG6SwCgyT7JO5OPb6FxMBBErzdN8gOxbCoAGAAAAAAAAP9XBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACvPcYPg4RyR455PWnYR33kK3pPEPnGX0aDmes1325KpgBYBgAAAAAA//d/AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
              "index": 2,
              "type_name": "EV_EFI_GPT_EVENT"
            },
            {
              "details": {
                "device_paths": [
                  "ACPI(PNP0A03,0)",
                  "Pci(1,1)",
                  "Path(3,1,00000000)",
                  "HD(2,GPT,A16F8F93-3071-4410-AF37-4DF203B16C2A,0x1800,0x64000)",
                  "File(\\EFI\\anolis\\shimx64.efi)"
                ]
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "73ce7699eeb49be3921196bc6bce506adb8d7ab8c6194eb7a20b939451f4d84a"
                }
              ],
              "event": "GOBtfQAAAADwlA4AAAAAAAAAAAAAAAAAfAAAAAAAAAACAQwA0EEDCgAAAAABAQYAAQEDAQgAAAAAAAQBKgACAAAAABgAAAAAAAAAQAYAAAAAAJOPb6FxMBBErzdN8gOxbCoCAgQENABcAEUARgBJAFwAYQBuAG8AbABpAHMAXABzAGgAaQBtAHgANgA0AC4AZQBmAGkAAAB//wQA",
              "index": 2,
              "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION"
            },
            {
              "details": {
                "string": "MokList"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "ea9e5e0a8e5a19bc3d7b1ea0f250a6d2500208278a99dec5baba3cacf53ac351"
                }
              ],
              "event": "TW9rTGlzdAA=",
              "index": 3,
              "type_name": "EV_IPL"
            },
            {
              "details": {
                "string": "MokListX"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "9938145964640087730b5a8978b4af58bed8ee6b14abf302f8c7e8b66f91a6d2"
                }
              ],
              "event": "TW9rTGlzdFgA",
              "index": 3,
              "type_name": "EV_IPL"
            },
            {
              "details": {
                "unicode_name": "SbatLevel",
                "unicode_name_length": 9,
                "variable_data": "c2JhdCwxLDIwMjEwMzAyMTgK",
                "variable_data_length": 18,
                "variable_name": "50ab5d60-46e0-0043-abb6-3dd810dd8b23"
              },
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "54ec273cb36f668364085a297dc41c0d479e439934fac9d22246f28fa7fb719f"
                }
              ],
              "event": "UKtdYEbgAEOrtj3YEN2LIwkAAAAAAAAAEgAAAAAAAABTAGIAYQB0AEwAZQB2AGUAbABzYmF0LDEsMjAyMTAzMDIxOAo=",
              "index": 1,
              "type_name": "EV_EFI_VARIABLE_AUTHORITY"
            },
            {
              "details": {
                "string": "MokListTrusted"
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "799b719ac031fc89c6d8925a487dad07308f837b7ab7bbc7cebd3a4118fd2f38"
                }
              ],
              "event": "TW9rTGlzdFRydXN0ZWQA",
              "index": 3,
              "type_name": "EV_IPL"
            },
            {
              "details": {
                "device_paths": [
                  "File(\\EFI\\anolis\\grubx64.efi)"
                ]
              },
              "digest_matches_event": false,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "a2267b27d1723fb0a17b9c0f2c013635b5e732b0243db1e32ed213119ea26782"
                }
              ],
              "event": "GIA+fQAAAADwAyIAAAAAAAAAAAAAAAAAOAAAAAAAAAAEBDQAXABFAEYASQBcAGEAbgBvAGwAaQBzAFwAZwByAHUAYgB4ADYANAAuAGUAZgBpAAAAf/8EAA==",
              "index": 2,
              "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION"
            },
            {
              "details": {
                "string": "Exit Boot Services Invocation"
              },
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "7f502fbbfffb4d84bf6dc743fbf59c8bc89ccf90ddcae22196b52b9a3247dd1f"
                }
              ],
              "event": "RXhpdCBCb290IFNlcnZpY2VzIEludm9jYXRpb24=",
              "index": 2,
              "type_name": "EV_EFI_ACTION"
            },
            {
              "details": {
                "string": "Exit Boot Services Returned with Success"
              },
              "digest_matches_event": true,
              "digests": [
                {
                  "alg": "SM3",
                  "digest": "94949e0c7e1e83e4609c1f5077b0500f2b638d9ca5fc7d2ffd836283ca511fa3"
                }
              ],
              "event": "RXhpdCBCb290IFNlcnZpY2VzIFJldHVybmVkIHdpdGggU3VjY2Vzcw==",
              "index": 2,
              "type_name": "EV_EFI_ACTION"
            }
          ],
          "user_pubkey_digest": "0000000000000000000000000000000000000000000000000000000000000000",
          "version": "2",
          "vm_id": "00000000000000000000000000000000",
          "vm_version": "00000000000000000000000000000000"
}
```