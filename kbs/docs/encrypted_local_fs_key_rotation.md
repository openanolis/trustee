# EncryptedLocalFs 密钥轮转

`EncryptedLocalFs` 资源后端会用一把 RSA 公钥来包裹每个资源的内容加密密钥
(CEK),因此解密资源时必须使用对应的 RSA 私钥。如果直接替换私钥,所有用旧密钥
加密过的资源都会立即无法解密。

为此,KBS **默认自管理密钥**:启用 `EncryptedLocalFs` 时它自己生成密钥对,轮转也
由它自己完成。对运维/管控而言,轮转就是**调一个接口**的事——KBS 自动完成"生成新
密钥 → 重包裹所有资源 → 清理旧密钥",轮转完再调一个接口把新公钥读走即可。**无需
手动生成密钥,无需改配置,无需重启。**

> 阅读本文前,建议你已经熟悉
> [`EncryptedLocalFs` 后端](./resource_storage_backend.md#encrypted-local-file-system-backend)
> 及其 JSON 信封(envelope)格式。加密在客户端完成,KBS 只负责解密、重包裹与密钥
> 生命周期管理。

## 两种密钥来源

- **KBS 自管理(默认,推荐)**:配置 `key_dir`(不配则用默认目录
  `/opt/confidential-containers/kbs/resource-keys`)。KBS 首次启动时在该目录生成
  一对 RSA 密钥;目录中**最新**的密钥即当前主密钥(rewrap 目标、`pubkey` 返回的
  公钥)。一键 `rotate` 接口完成整套轮转。
- **自带密钥(BYOK)**:配置 `private_key_path`(主/ rewrap 目标)以及可选的
  `private_key_dir` / `private_key_paths`(仅用于解密)。此模式下用 `reload` /
  `rewrap` 等更底层的接口轮转(见文末)。两者也可并存:managed 的 `key_dir` 为主,
  BYOK 的密钥作为只读解密来源(便于从 BYOK 迁移到 managed)。

## admin API

下列接口都需要 admin 的 `Bearer` 令牌(由 `[admin]` 段 `auth_public_key` 对应
私钥签发,详见 [Admin API 配置](./config.md#admin-api-configuration))。下文
`$KBS` 表示 KBS 地址,`$ADMIN_TOKEN` 表示该令牌。

| 接口 | 方法 | 作用 |
|------|------|------|
| `/kbs/v0/resource/rotate` | POST | **一键轮转(自管理)**:生成新密钥 → 重包裹全部资源 → 退役旧密钥。 |
| `/kbs/v0/resource/pubkey` | GET  | 读取当前主公钥(PEM),供客户端加密。 |
| `/kbs/v0/resource/reload` | POST | 重读配置的密钥并原子换环(免重启)。 |
| `/kbs/v0/resource/rewrap` | POST | 把所有资源 CEK 重包裹到当前主密钥(不生成新密钥)。 |

## 自管理模式:一键轮转(推荐)

### 1. 配置(通常无需任何密钥配置)

```toml
[[plugins]]
name = "resource"
type = "EncryptedLocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
# key_dir 默认为 /opt/confidential-containers/kbs/resource-keys;需要时再显式覆盖。
```

KBS 首次启动即在 `key_dir` 生成一对密钥。客户端先取公钥:

```shell
curl -s "$KBS/kbs/v0/resource/pubkey" -H "Authorization: Bearer $ADMIN_TOKEN" > resource-public.pem
# 用该公钥加密资源(见 kbs/sdk/python/encrypt_resource.py),再写入 KBS。
```

### 2. 轮转 —— 一个接口搞定

```shell
curl -X POST "$KBS/kbs/v0/resource/rotate" -H "Authorization: Bearer $ADMIN_TOKEN"
# -> {"public_key":"-----BEGIN PUBLIC KEY-----\n...","rewrapped":100,"skipped":28,"failed":0,"retired_keys":1}
```

这一个调用里,KBS 自动完成:

1. 生成一对新 RSA 密钥(作为新的主密钥)。
2. 把所有存量资源的 CEK 重包裹到新主密钥(只改 `enc_key`/`alg`,不动 AES 密文)。
3. 若全部成功(`failed == 0`),退役并删除旧的自管理密钥(`retired_keys` 为删除
   数量);**若有资源 rewrap 失败,则保留旧密钥**以保证其仍可解密,`failed` 会
   大于 0,需排查后重试。

返回体里的 `public_key` 就是新公钥。

### 3. 取走新公钥

```shell
curl -s "$KBS/kbs/v0/resource/pubkey" -H "Authorization: Bearer $ADMIN_TOKEN" > resource-public.pem
```

之后客户端用新公钥加密新资源即可。整个轮转无重启、无手动生成密钥、无改配置。

> `rotate` 会就地重写仓库中的资源文件,需要 KBS 对仓库有写权限。建议在维护窗口执行,
> 避免与对同一资源的写入并发;轮转期间若客户端仍用旧公钥写入新资源,请在 `rotate`
> 完成后改用新公钥(或对这些资源再跑一次 `rewrap`)。

## 自带密钥(BYOK)模式的轮转

若你坚持自管密钥材料(`private_key_path` 等),则没有一键 `rotate`(它属于自管理
模式),改用以下手动流程:

1. 把旧主密钥归档进 `private_key_dir`,把新私钥写到 `private_key_path`,调用
   `POST /kbs/v0/resource/reload` 热加载(免重启)。
2. 调用 `POST /kbs/v0/resource/rewrap` 把存量资源重包裹到新主密钥。
3. 从 `private_key_dir` 删除旧密钥,再次 `reload`。

仓库对 KBS 只读、需带外迁移时,用 `kbs/sdk/python/reencrypt_resource.py`(旧私钥
解、新公钥重加密,支持 `--check` 校验)。

## 说明

- 密钥环只用于**解密**;加密在客户端进行,新资源请用最新公钥加密。
- 自管理密钥由 KBS 生成并以 `0600` 权限保存在 `key_dir`(目录 `0700`);文件名形如
  `mkey-<纳秒时间戳>.pem`,最新者为当前主密钥。
- 主密钥的公钥由其私钥推导,无需单独配置或分发私钥。
- 仅当较靠前的密钥解密失败时,才会对每把额外密钥多做一次 RSA 运算,因此轮转过渡期
  保留少量旧密钥的开销可忽略。
