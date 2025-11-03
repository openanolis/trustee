# 度量参考值

OpenAnolis系统为Trustee提供了配套的度量值参考值计算工具`cryptpilot`，对于一个Alinux/OpenAnolis操作系统的镜像（qcow2格式），可以一键计算出其启动度量链的参考值（grub-shim-initrd-kernel-kernel_cmdline）

# 使用方法

### 安装cryptpilot

在一个Alinux3/anolis8/anolis23系统中，直接使用如下命令安装`cryptpilot`

```shell
yum install cryptpilot
```

### 对给定的qcow2格式镜像计算参考值

```shell
cryptpilot fde show-reference-value \
    --disk /path/to/alinux_guest.qcow2 \
    --hash-algo sha1 \
    > ./reference-value.json
```

其中，`--disk`参数指定qcow2系统镜像路径，`--hash-algo`指定要计算的参考值的度量算法，支持如下几种：

- `sm3`
- `sha1`
- `sha256`
- `sha384`

### 参考值示例

上一步中的命令会直接输出trustee的RVPS（参考值提供服务）能够理解的json格式参考值列表，示例：

```json
{
  "measurement.kernel_cmdline.SHA-1": [
    "92841b2f3c0740ac662c74fe90bda526d40655db",
    "8399241d072d7d38ad0f53309bc226c7ed774dec"
  ],
  "measurement.kernel.SHA-1": [
    "0319d6c6472e168dd8081622b2ee5a88ce977457"
  ],
  "measurement.initrd.SHA-1": [
    "f2ac90ddb5520e6782a1bccf69b0a4a0b8f5ff27"
  ],
  "measurement.grub.SHA-1": [
    "94b31eb049948918ce988e0ef1a80521db3a01c8"
  ],
  "measurement.shim.SHA-1": [
    "54377e45046bd7e9d7734a9d693dc3e9e529f2da"
  ],
  "kernel_cmdline": [
    "grub_kernel_cmdline /vmlinuz-5.10.134-19.1.al8.x86_64 root=UUID=862cebbd-06c1-4349-9a06-ea8766a04bf3 ro rhgb quiet cgroup.memory=nokmem crashkernel=0M-2G:0M,2G-8G:192M,8G-128G:256M,128G-376G:384M,376G-:448M spec_rstack_overflow=off vring_force_dma_api kfence.sample_interval=100 kfence.booting_max=0-2G:0,2G-32G:2M,32G-:32M preempt=none biosdevname=0 net.ifnames=0 console=tty0 console=ttyS0,115200n8 noibrs nvme_core.io_timeout=4294967295 nvme_core.admin_timeout=4294967295 cryptomgr.notests rcupdate.rcu_cpu_stall_timeout=300",
    "grub_kernel_cmdline (hd0,gpt3)/boot/vmlinuz-5.10.134-19.1.al8.x86_64 root=UUID=862cebbd-06c1-4349-9a06-ea8766a04bf3 ro rhgb quiet cgroup.memory=nokmem crashkernel=0M-2G:0M,2G-8G:192M,8G-128G:256M,128G-376G:384M,376G-:448M spec_rstack_overflow=off vring_force_dma_api kfence.sample_interval=100 kfence.booting_max=0-2G:0,2G-32G:2M,32G-:32M preempt=none biosdevname=0 net.ifnames=0 console=tty0 console=ttyS0,115200n8 noibrs nvme_core.io_timeout=4294967295 nvme_core.admin_timeout=4294967295 cryptomgr.notests rcupdate.rcu_cpu_stall_timeout=300"
  ]
}
```

可以直接以上述内容作为请求体payload，调用Trustee的[注册参考值API](../trustee-gateway/trustee_gateway_api.md#42-注册参考值-register-reference-value)，完成参考值的设置。