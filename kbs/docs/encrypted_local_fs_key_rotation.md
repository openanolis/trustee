# EncryptedLocalFs 密钥轮转

`EncryptedLocalFs` 资源后端会用一把 RSA 公钥来包裹每个资源的内容加密密钥
(CEK),因此解密资源时必须使用对应的 RSA 私钥。如果直接替换私钥,所有用旧密钥
加密过的资源都会立即无法解密。

为此,`EncryptedLocalFs` 把密钥轮转设计成**零停机、无需手动迁移文件、无需改配置
重启**,整个过程通过 admin API 驱动:

- **密钥环(key ring)**:KBS 同时持有多把解密私钥。`private_key_path` 是**主
  密钥**(解密时最先尝试,也是重包裹的目标);`private_key_dir` 是一个存放额外
  `*.pem` 私钥的目录;`private_key_paths` 则按路径列出额外私钥。读取时逐把尝试,
  所以用旧密钥加密的资源在轮转期间照常可解。
- **热加载**:`POST /kbs/v0/resource/reload`(需 admin 鉴权)会重新读取主密钥
  文件、重新扫描 `private_key_dir`、重新读取 `private_key_paths`,并原子地替换
  密钥环,**无需重启**。
- **服务端重包裹(rewrap)**:`POST /kbs/v0/resource/rewrap`(需 admin 鉴权)
  遍历所有存量资源,把每个资源的 CEK 重新用**主密钥**的公钥包裹(公钥由主私钥直接
  推导,无需外部传入)。只改写信封的 `enc_key`/`alg` 字段,**AES-256-GCM 密文原样
  不动**;已经在主密钥上的资源、以及明文资源都会被跳过。

> 阅读本文前,建议你已经熟悉
> [`EncryptedLocalFs` 后端](./resource_storage_backend.md#encrypted-local-file-system-backend)
> 及其 JSON 信封(envelope)格式。加密在客户端完成,KBS 只负责解密与重包裹。

## 密钥环的工作方式

后端按以下顺序构建解密私钥列表:

1. `private_key_path` —— 主(当前)密钥,最先尝试,也是 rewrap 的目标。
2. `private_key_dir` 中的 `*.pem` —— 按文件名排序依次尝试。
3. `private_key_paths` —— 按列表顺序依次尝试。

每次读取加密资源时,KBS 按上述顺序尝试,返回第一把成功解密的密钥的结果。错误的
密钥绝不会产生错误数据:它会被 RSA padding 校验、CEK 长度检查,或最终的
AES-256-GCM 认证标签(tag)所拒绝。如果资源是加密信封但**没有任何**已配置密钥能
解开,读取直接失败(绝不会把密文当明文返回)。明文(非信封)资源仍原样透传。

至少要配置一把密钥(三种来源任一即可)。rewrap 需要有主密钥(`private_key_path`)
作为目标,否则会报错。

配置示例:

```toml
[[plugins]]
name = "resource"
type = "EncryptedLocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
private_key_path = "/etc/kbs/resource-keys/primary.pem"   # 主密钥(rewrap 目标,最先尝试)
private_key_dir  = "/etc/kbs/resource-keys/archive"       # 退役密钥,仅保留用于解密
```

## admin API 调用

`reload` 与 `rewrap` 都是 admin 接口,需要在请求头携带 admin 的 `Bearer` 令牌
(由 `[admin]` 段的 `auth_public_key` 对应私钥签发;详见
[Admin API 配置](./config.md#admin-api-configuration))。下文示例用
`$ADMIN_TOKEN` 表示该令牌,`$KBS` 表示 KBS 地址。

## 轮转步骤

假设 KBS 当前主密钥文件是 `/etc/kbs/resource-keys/primary.pem`,退役密钥目录是
`/etc/kbs/resource-keys/archive`,现在要轮转到一对新密钥。

### 1. 生成新密钥对

```shell
openssl genrsa -out /tmp/resource-private-new.pem 3072
openssl rsa -in /tmp/resource-private-new.pem -pubout -out /tmp/resource-public-new.pem
```

### 2. 归档旧主密钥,换上新主密钥,然后热加载

```shell
# 旧主密钥移入归档目录,继续用于解密存量资源
cp /etc/kbs/resource-keys/primary.pem /etc/kbs/resource-keys/archive/old-$(date +%Y%m%d).pem
# 新私钥写为主密钥
cp /tmp/resource-private-new.pem /etc/kbs/resource-keys/primary.pem

# 热加载,无需重启
curl -X POST "$KBS/kbs/v0/resource/reload" -H "Authorization: Bearer $ADMIN_TOKEN"
# -> {"reloaded_keys": 2}
```

此刻:存量资源(旧公钥加密)仍可用归档的旧密钥解密;新资源则应由客户端/控制台用
**新公钥**(`resource-public-new.pem`)加密后写入。

### 3. 服务端重包裹存量资源

```shell
curl -X POST "$KBS/kbs/v0/resource/rewrap" -H "Authorization: Bearer $ADMIN_TOKEN"
# -> {"total": 128, "rewrapped": 100, "skipped": 28, "failed": 0}
```

KBS 会把所有用旧密钥加密的资源就地重包裹到新主密钥(只换 `enc_key`,不重新加密
数据)。已在新主密钥上的资源、明文资源会计入 `skipped`;无法用任何已配置密钥解密
的资源计入 `failed` 并记录日志,但不会中断整个过程。可重复调用,幂等。

> rewrap 会就地重写仓库目录中的文件,需要 KBS 对仓库有写权限。建议在维护窗口执行,
> 避免与对同一资源的写入并发。

### 4. 退役旧密钥

确认 `rewrap` 后 `failed` 为 0、所有资源都已迁移,再删除归档目录里的旧密钥并热加载:

```shell
rm /etc/kbs/resource-keys/archive/old-*.pem
curl -X POST "$KBS/kbs/v0/resource/reload" -H "Authorization: Bearer $ADMIN_TOKEN"
# -> {"reloaded_keys": 1}
```

安全销毁旧私钥材料。轮转至此完成 —— 全程无重启、无手动改写文件内容、客户端无感。

## 仓库只读 / 带外迁移(可选)

如果你的部署把资源仓库对 KBS 设为只读、由控制台带外写入,服务端 `rewrap` 不适用。
此时仍可用热加载免重启,迁移则用带外脚本
`kbs/sdk/python/reencrypt_resource.py` 完成:它用旧私钥解出信封、用新公钥重新加密,
支持原地重写与 `--check` 校验。

```shell
kbs/sdk/python/reencrypt_resource.py \
    --old-privkey /etc/kbs/resource-keys/archive/old.pem \
    --new-pubkey  /tmp/resource-public-new.pem \
    --in  /path/to/resource --out /path/to/resource
```

## 说明

- 密钥环只用于**解密**;加密在客户端进行,新资源请用新公钥加密。
- 密钥可以是 PKCS#8 或 PKCS#1 的 PEM 格式;主密钥的公钥由其私钥推导,无需单独配置。
- 仅当较靠前的密钥解密失败时,才会对每把额外密钥多做一次 RSA 运算,因此轮转期间
  保留少数几把密钥的开销可忽略。
