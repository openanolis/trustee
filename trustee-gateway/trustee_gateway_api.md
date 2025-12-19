# Trustee Gateway API 文档

## 目录

### [1. KBS API (`/api/kbs/v0`)](#kbs-api-apikbsv0)
- [1.1 认证 (Authentication)](#11-认证-authentication)
- [1.2 证明 (Attestation)](#12-证明-attestation)
- [1.3 设置认证策略 (Set Attestation Policy)](#13-设置认证策略-set-attestation-policy)
- [1.4 获取认证策略 (Get Attestation Policy)](#14-获取认证策略-get-attestation-policy)
- [1.5 删除认证策略 (Delete Attestation Policy)](#15-删除认证策略-delete-attestation-policy)
- [1.6 列出认证策略 (List Attestation Policies)](#16-列出认证策略-list-attestation-policies)
- [1.7 设置资源策略 (Set Resource Policy)](#17-设置资源策略-set-resource-policy)
- [1.8 获取资源策略 (Get Resource Policy)](#18-获取资源策略-get-resource-policy)
- [1.9 获取资源 (Get Resource)](#19-获取资源-get-resource)
- [1.10 设置资源 (Set Resource)](#110-设置资源-set-resource)
- [1.11 列出资源 (List Resources)](#111-列出资源-list-resources)
- [1.12 删除资源 (Delete Resource)](#112-删除资源-delete-resource)

### [2. AS API (`/api/attestation-service`)](#as-api-apiattestation-service)
- [2.1 证明 (Attestation)](#21-证明-attestation-1)
- [2.2 挑战 (Challenge)](#22-挑战-challenge)
- [2.3 获取证书 (Get Certificate)](#23-获取证书-get-certificate)

### [3. AS API (`/api/as`)](#as-api-apias)
- [3.1 证明 (Attestation)](#31-证明-attestation-2)
- [3.2 挑战 (Challenge)](#32-挑战-challenge-1)
- [3.3 获取证书 (Get Certificate)](#33-获取证书-get-certificate-1)

### [4. RVPS API (`/api/rvps`)](#rvps-api-apirvps)
- [4.1 查询参考值 (Query Reference Value)](#41-查询参考值-query-reference-value)
- [4.2 注册参考值 (Register Reference Value)](#42-注册参考值-register-reference-value)
- [4.3 删除参考值 (Delete Reference Value)](#43-删除参考值-delete-reference-value)

### [5. 审计 API (`/api/audit`)](#审计-api-apiaudit)
- [5.1 列出认证记录 (List Attestation Records)](#51-列出认证记录-list-attestation-records)
- [5.2 列出资源请求记录 (List Resource Requests)](#52-列出资源请求记录-list-resource-requests)

### [6. 健康检查 API (`/api`)](#6-健康检查-api-api)
- [6.1 基本健康检查](#61-基本健康检查)
- [6.2 服务健康检查](#62-服务健康检查)

### [7. 实例API (`/api/aa-instance`)](#7-实例api-apiaa-instance)
- [7.1 AA实例心跳](#71-aa实例心跳)
- [7.2 实例列表](#72-实例列表)

### [附录](#附录)
- [KBS认证头生成方法](#kbs认证头生成方法)

---

### KBS API (`**/api/kbs/v0**`)

这部分 API 主要用于处理与 Key Broker Service (KBS) 相关的操作。Gateway 通常作为代理将请求转发给后端 KBS 服务，但在某些情况下（如策略和资源列表、审计日志）会直接与自己的数据库交互。

#### 1.1 认证 (Authentication)

*   **端点:** `POST /kbs/v0/auth`
    
*   **说明:** 用于与后端 KBS 服务进行初始认证握手。Gateway 会将请求直接转发给配置的 KBS 服务，并将 KBS 的响应（包括状态码、头、Cookie 和响应体）直接返回给客户端。
    
*   **调用方法:**
    

```plaintext
curl -k -X POST http://<gateway-host>:<port>/api/kbs/v0/auth \
     -H 'Content-Type: application/json' \
     -d '{
             "version": "0.4.0",
             "tee": "tdx",
             "extra-params": "foo"
         }'
```

*   **请求头:**
    
    *   `Content-Type: application/json`
        
*   **请求体 (JSON - 由 KBS 定义):**
    
    *   参考 KBS OpenAPI 规范中的 `Request` schema:
        

```json
{
    "version": "string", // (必需) 协议版本，例如 "0.4.0"
    "tee": "string",     // (必需) TEE 类型。已知值: "tdx", "tpm", "csv"。后端 KBS 可能接受其他值（例如用于测试的 "sample"）。
    "extra-params": "string"   // 字符串，保留字段，用于可能的额外参数传递
}
```

*   **响应:**
    
    *   成功时，响应体、状态码和头由后端 KBS 服务决定。
        
        *   通常 KBS 返回 `200 OK`。
            
        *   响应体遵循 KBS OpenAPI 中的 `Challenge` schema，包含 `nonce` (必需) 和可选的 `extra-params`。
            
        *   KBS 通过 `Set-Cookie` 头设置 `kbs-session-id`。
            
    *   失败时，可能由 KBS 或 Gateway 返回错误。
        
*   **返回码:**
    
    *   `200 OK`: 认证流程启动成功 (由 KBS 返回)。
        
    *   `400 Bad Request`: 请求内容或格式不被 KBS 支持 (由 KBS 返回)。
        
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法读取请求体、无法转发请求给 KBS、无法读取 KBS 响应)。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他由 KBS 返回的状态码 (例如 5xx)_
        
*   **返回示例 (成功 - 由 KBS 返回):**
    

```json
{
    "nonce": "base64_encoded_nonce",
    "extra-params": { ... }
}
```

_响应头包含:_ `Set-Cookie: kbs-session-id=your-session-id; ...`

#### 1.2 证明 (Attestation)

*   **端点:** `POST /kbs/v0/attest`
    
*   **说明:** 用于向后端 KBS 服务提交 TEE 证据以进行验证。Gateway 会将请求转发给 KBS，并将 KBS 的响应返回给客户端。之后，Gateway 会**异步记录一条证明审计日志**到其数据库。
    
*   **调用方法:**
    

```shell
SESSION_ID="your-session-id" # 从 /auth 响应的 Cookie 中获取
curl -k -X POST http://<gateway-host>:<port>/api/kbs/v0/attest \
     -b "kbs-session-id=${SESSION_ID}" \
     -H 'Content-Type: application/json' \
     -d '{
             "runtime_data": {
                 "nonce": "base64_encoded_nonce",
                 "tee-pubkey": {
                     "alg": "RSA",
                     "k-mod": "base64_modulus",
                     "k-exp": "base64_exponent"
                 }
             },
             "init_data": {
                 "format": "toml",
                 "body": "base64_encoded_toml"
             },
             "tee_evidence": {
                 "primary_evidence": { ... },
                 "additional_evidence": "{...}"
             }
         }'
```

*   **请求头:**
    
    *   `Content-Type: application/json`
        
    *   `Cookie: kbs-session-id=<session-id>` (必需，由 KBS 验证)
        
    *   `AAInstanceInfo: '{"image_id":"aliyun_3_9_x64_20G_uefi_alibase_20231219.vhd","instance_id":"i-bp13wqyr5ik6l669424n","instance_name":"test-cc","owner_account_id":"1242424451954755"}'` 
        
*   **请求体 (JSON - 由 KBS 定义):**
    
    *   参考 KBS OpenAPI 规范中的 `Attestation` schema:
        

```json
{
    "runtime_data": {     // (必需) 运行时数据，包含nonce和TEE公钥信息
        "nonce": "string", // Base64编码的nonce
        "tee-pubkey": {    // TEE公钥信息 (PublicKey Schema，具体字段取决于 alg)
            "alg": "string",   // 例如 "RSA", "ECDSA"
            "k-mod": "string", // Base64 编码的 RSA 模数 (如果 alg="RSA")
            "k-exp": "string"  // Base64 编码的 RSA 公钥指数 (如果 alg="RSA")
        }
    },
    "init_data": {        // (可选) 初始化数据
        "format": "string", // 格式，例如 "toml"
        "body": "string"    // Base64编码的数据体
    },
    "tee_evidence": {     // (必需) TEE证据，支持复合证据
        "primary_evidence": {},     // 主要证据
        "additional_evidence": "{}" // 额外证据的JSON字符串
    }
}
```


*   **响应:**
    
    *   成功时，响应体、状态码和头由后端 KBS 服务决定。
        
        *   通常 KBS 返回 `200 OK`。
            
        *   响应体遵循 KBS OpenAPI 中的 `AttestationToken` schema
            
    *   失败时，可能由 KBS 或 Gateway 返回错误。
        
    *   无论成功失败，Gateway 都会**异步记录审计日志** (`AttestationRecord`)，包含客户端 IP、会话 ID、请求体、KBS 返回的状态码、是否成功 (`仅当 KBS 返回 200 时为 true`) 以及时间戳。
        
*   **返回码:**
    
    *   `200 OK`: 证明成功 (由 KBS 返回)。
        
    *   `401 Unauthorized`: Session ID 无效或过期 (由 KBS 返回)。
        
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法读取请求体、无法转发请求给 KBS、无法读取 KBS 响应)。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他由 KBS 返回的状态码 (例如 4xx 证据验证失败, 5xx)_
        
*   **返回示例 (成功 - 返回证明结果令牌):**
    

```json
{
    "token": "base64_encoded_attestation_token" // 标准的JWT格式令牌，包含证明结果和表征TEE状态的声明集
}
```

#### 1.3 设置认证策略 (Set Attestation Policy)

*   **端点:** `POST /kbs/v0/attestation-policy`
    
*   **说明:** 用于设置或更新 KBS 的认证策略。Gateway 会首先解析请求体以获取策略信息，然后将**原始请求**转发给 KBS。如果 KBS 返回成功状态码 (`200`, `201`, `204`)，Gateway 会尝试将请求体中的策略内容 (Base64 解码后) 连同策略 ID、类型和元数据**存储在 Gateway 自己的数据库中**。最终将 KBS 的响应返回给客户端。
    
*   **调用方法:**
    

```shell
POLICY_CONTENT=$(base64 -w0 policy.rego) # 将策略文件内容进行 Base64 编码
curl -k -X POST http://<gateway-host>:<port>/api/kbs/v0/attestation-policy \
     -H 'Content-Type: application/json' \
     -d '{
             "type": "rego",
             "policy_id": "my-policy-v1",
             "policy": "'"${POLICY_CONTENT}"'"
         }'
```

*   **请求头:**
    
    *   `Content-Type: application/json`
        
    *   需要 KBS 要求的认证头（生成方法见附录）： `Authorization: Bearer <token>`
        
*   **请求体 (JSON):**
    

```json
{
    "type": "string",       // (必需) 策略类型 (例如 "rego")。其有效性由 KBS 判断。
    "policy_id": "string",  // (必需) 策略的唯一标识符。
    "policy": "string"      // (必需) Base64 编码后的策略内容。
}
```

_Gateway 会在转发前尝试解析此结构。_

*   **响应:**
    
    *   响应体和状态码由后端 KBS 服务决定。
        
    *   如果 KBS 返回 `200 OK`, `201 Created`, 或 `204 No Content`，Gateway 会**尝试将策略存入本地数据库**。解码或存储失败会被记录在 Gateway 日志中，但**不影响**返回给客户端的 KBS 响应。
        
*   **返回码:**
    
    *   `200 OK / 201 Created / 204 No Content`: 设置成功 (由 KBS 返回)。Gateway 会尝试本地存储。
        
    *   `400 Bad Request`:
        
        *   由 Gateway 返回: 请求体不是有效的 JSON 或缺少必需字段。响应体 `{"error": "Invalid attestation policy format"}`。
            
        *   由 KBS 返回: 请求格式错误或策略无效。
            
    *   `401 Unauthorized / 403 Forbidden`: 无权限 (由 KBS 返回)。
        
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法读取请求体、无法转发请求给 KBS、无法读取 KBS 响应)。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他由 KBS 返回的状态码_
        
*   **返回示例 (成功 - KBS 返回空内容):** _状态码: 200_
    

![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/fba9b821-6f2b-4e55-b6bc-7efd938296b1.png)

#### 1.4 获取认证策略 (Get Attestation Policy)

*   **端点:** `GET /kbs/v0/attestation-policy/{id}`
    
*   **说明:** 获取指定 ID 的认证策略**。**
    
*   **调用方法:**
    

```shell
curl -k http://<gateway-host>:<port>/api/kbs/v0/attestation-policy/my-policy-v1
```

*   **请求头:** 无
    
*   **请求参数:**
    
    *   `id` (路径参数, string, 必需): 要获取的策略 ID。
        
*   **请求体:** 无
    
*   **响应:**
    
    *   成功时，返回策略信息的 base64编码。
        
    *   失败时，返回错误信息。
        
*   **返回码:**
    
    *   `200 OK`: 成功找到策略。
        
    *   `401`: 指定 ID 的策略不存在。响应体`{"type":"https://github.com/confidential-containers/kbs/errors/AttestationError","detail":"Attestation error: Get Attestation Policy failed"}`
        
*   **返回示例 (成功):**
    

![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/aeb02d19-60d3-40cb-8e8d-7b4eb497ca84.png)

#### 1.5 删除认证策略 (Delete Attestation Policy)

*   **端点:** `DELETE /kbs/v0/attestation-policy/{id}`
    
*   **说明:** 删除指定ID的认证策略。Gateway会将请求转发给KBS，并将KBS的响应返回给客户端。
    
*   **调用方法:**
    

```shell
curl -k -X DELETE http://<gateway-host>:<port>/api/kbs/v0/attestation-policy/my-policy-v1 \
     -H "Authorization: Bearer <token>"
```

*   **请求头:**
    
    *   需要KBS要求的认证头（生成方法见附录）： `Authorization: Bearer <token>`
        
*   **请求参数:**
    
    *   `id` (路径参数, string, 必需): 要删除的策略ID。
        
*   **请求体:** 无
    
*   **响应:**
    
    *   成功时，通常返回空响应体和状态码204。
        
    *   失败时，返回错误信息。
        
*   **返回码:**
    
    *   `204 No Content`: 成功删除策略。
        
    *   `401 Unauthorized / 403 Forbidden`: 无权限删除该策略。
        
    *   `404 Not Found`: 指定ID的策略不存在。
        
    *   `500 Internal Server Error`: Gateway内部错误或转发请求失败。响应体通常为`{"error": "<错误信息>"}`。
        
*   **返回示例 (成功):**

_状态码: 204 No Content_

_响应体: (空)_

#### 1.6 列出认证策略 (List Attestation Policies)

*   **端点:** `GET /kbs/v0/attestation-policies`
    
*   **说明:** 列出所有存储的认证策略。
    
*   **调用方法:**
    

```shell
curl -k http://<gateway-host>:<port>/api/kbs/v0/attestation-policies
```

*   **请求头:** 无
    
*   **请求参数:** 无
    
*   **请求体:** 无
    
*   **响应:**
    
    *   成功时，返回包含策略哈希列表的 JSON 数组 。
        
    *   失败时，返回错误信息。
        
*   **返回码:**
    
    *   `200 OK`: 成功。
        
*   **返回示例 (成功):**
    

```json
{
    "test": "aExY1n-_lngY_s6zEVFzGWf161TdTmQFxMyu8g3gUSSRrDfvkXFM7tLUXU3BbzMk",
    "default": "aExY1n-_lngY_s6zEVFzGWf161TdTmQFxMyu8g3gUSSRrDfvkXFM7tLUXU3BbzMk"
}
```

![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/c798e992-f0c4-41e3-809a-292e135f8f58.png)

#### 1.7 设置资源策略 (Set Resource Policy)

*   **端点:** `POST /kbs/v0/resource-policy`
    
*   **说明:** 用于设置 KBS 的资源访问策略。Gateway 会将请求**直接转发**给配置的 KBS 服务，并将 KBS 的响应返回给客户端。
    
*   **调用方法:** (具体请求体格式和认证方式取决于 KBS)
    

```shell
curl -k -X POST http://<gateway-host>:<port>/api/kbs/v0/resource-policy \
     -H 'Content-Type: application/json' \
     -H 'Authorization: Bearer <token>' \
     -d '{"policy": "..."}'
```

*   **请求头:**
    
    *   `Content-Type`: (必需，由 KBS 定义，例如 `application/json`)
        
    *   需要 KBS 要求的认证头（生成方法见附录）： `Authorization: Bearer <token>`
        
*   **请求体:** 由后端 KBS 定义 (参考 KBS OpenAPI `ResourcePolicy` schema)。
    
*   **响应:** 响应体和状态码由后端 KBS 服务决定。
    
*   **返回码:**
    
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法读取请求体、无法转发请求给 KBS、无法读取 KBS 响应)。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他状态码完全由 KBS 决定 (例如 200, 204, 400, 401, 403, 5xx)_。
        

![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/9b5e911d-1731-417a-b539-295caec63556.png)

#### 1.8 获取资源策略 (Get Resource Policy)

*   **端点:** `GET /kbs/v0/resource-policy`
    
*   **说明:** 用于获取 KBS 的资源访问策略。Gateway 会将请求**直接转发**给配置的 KBS 服务，并将 KBS 的响应返回给客户端。
    
*   **调用方法:** 
    

```shell
curl -k http://<gateway-host>:<port>/api/kbs/v0/resource-policy \
      -H "Authorization: Bearer <token>"
```

*   **请求头:** 需要 KBS 要求的认证头（生成方法见附录）`Authorization: Bearer <token>`
    
*   **请求参数:** 无
    
*   **请求体:** 无
    
*   **响应:** 响应体和状态码由后端 KBS 服务决定。
    
*   **返回码:**
    
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法读取请求体、无法转发请求给 KBS、无法读取 KBS 响应)。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他状态码完全由 KBS 决定 (例如 200, 401, 403, 404, 5xx)_。
        
*   ![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/3b899bc4-8f3d-470e-8029-20dfccd54ead.png)
    

#### 1.9 获取资源 (Get Resource)

*   **端点:** `GET /kbs/v0/resource/{repository}/{type}/{tag}`
    
*   **说明:** 从 KBS 获取指定标识的资源（如密钥、配置等）。Gateway 会将请求转发给 KBS，并将 KBS 的响应返回给客户端。之后，Gateway 会**异步记录一条资源请求审计日志**到其数据库。
    
*   **调用方法:**
    

```shell
SESSION_ID="your-session-id" # 如果 KBS 需要会话认证
curl -k -b "kbs-session-id=${SESSION_ID}" \
     -H "Authorization: Bearer <token>"
     http://<gateway-host>:<port>/api/kbs/v0/resource/my-repo/key/latest
```

*   **请求头:**
    
    *   需要 `Cookie: kbs-session-id=<session-id>`或认证头： `Authorization: Bearer <token>`认证头这里的<token>是远程证明token（即调用`/kbs/v0/attest`返回体中的那个token）
        
    *   `AAInstanceInfo: '{"image_id":"aliyun_3_9_x64_20G_uefi_alibase_20231219.vhd","instance_id":"i-bp13wqyr5ik6l669424n","instance_name":"test-cc","owner_account_id":"1242424451954755"}'` 
        
*   **请求参数:**
    
    *   `repository` (路径参数, string, 必需): 资源所属的仓库名。
        
    *   `type` (路径参数, string, 必需): 资源的类型。
        
    *   `tag` (路径参数, string, 必需): 资源的标签或版本。
        
*   **请求体:** 无
    
*   **响应:**
    
    *   响应体、状态码和头由后端 KBS 服务决定。
        
        *   成功时 KBS 通常返回 `200 OK`，响应体为 JWE 格式 (`application/jwe`), 可使用TEE密钥解密
            
    *   无论成功失败，Gateway 都会**异步记录审计日志** (`ResourceRequest`)，包含客户端 IP、会话 ID、资源标识符 (repo, type, tag)、方法 ("GET")、KBS 返回的状态码、是否成功 (`仅当 KBS 返回 200 时为 true`) 以及时间戳。
        
*   **返回码:**
    
    *   `200 OK`: 成功获取资源 (由 KBS 返回)。
        
    *   `401 Unauthorized`: Session ID 无效或token认证失败 (由 KBS 返回)。
        
    *   `403 Forbidden`: 无权限获取该资源 (由 KBS 返回)。
        
    *   `404 Not Found`: 资源不存在 (由 KBS 返回)。
        
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法转发请求给 KBS、无法读取 KBS 响应)。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他由 KBS 返回的状态码 (例如 5xx)_
        
*   **返回示例 (成功 - 由 KBS 返回 JWE):**_状态码: 200 OK响应头:_ `_Content-Type: application/jwe_`_响应体: (JWE 格式数据)_
    

#### 1.10 设置资源 (Set Resource)

*   **端点:** `POST /kbs/v0/resource/{repository}/{type}/{tag}`
    
*   **说明:** 向 KBS 上传或更新指定标识的资源。Gateway 会将请求转发给 KBS。如果 KBS 返回成功状态码 (`200`, `201`, `204`)，Gateway 会将资源的元数据**存储在 Gateway 自己的数据库中**。之后，Gateway 会**异步记录一条资源请求审计日志**。最终将 KBS 的响应返回给客户端。
    
*   **调用方法:** (具体认证方式和请求体格式取决于 KBS)
    

```shell
curl -k -X POST http://<gateway-host>:<port>/api/kbs/v0/resource/my-repo/my-type/my-tag  \
     -H 'Content-Type: application/octet-stream' \
     -H "Authorization: Bearer <token>" \
     -d "12345"
```

*   **请求头:**
    
    *   `Content-Type`: (必需，取决于资源类型和 KBS 要求，例如 `application/octet-stream`, `application/json`, `*/*`)
        
    *   需要 KBS 要求的认证头（生成方法见附录）： `Authorization: Bearer <token>`
        
*   **请求参数:**
    
    *   `repository` (路径参数, string, 必需): 资源所属的仓库名。
        
    *   `type` (路径参数, string, 必需): 资源的类型。
        
    *   `tag` (路径参数, string, 必需): 资源的标签或版本。_(KBS OpenAPI V0.4.0 标记 repository 为可选，但 Gateway 路由需要它)_
        
*   **请求体:** 资源内容，格式由 `Content-Type` 指定，具体由 KBS 处理。
    
*   **响应:**
    
    *   响应体和状态码由后端 KBS 服务决定。
        
    *   如果 KBS 返回 `200 OK`, `201 Created`, 或 `204 No Content`，Gateway 会**将资源元数据存入本地数据库** (包含 repo, type, tag 和 "Set by..." metadata)。存储失败会被记录在 Gateway 日志中，但**不影响**返回给客户端的 KBS 响应。
        
    *   无论成功失败，Gateway 都会**异步记录审计日志** (`ResourceRequest`)，包含客户端 IP、会话 ID、资源标识符、方法 ("POST")、KBS 返回的状态码、是否成功 (`当 KBS 返回 200, 201 或 204 时为 true`) 以及时间戳。
        
*   **返回码:**
    
    *   `200 OK / 201 Created / 204 No Content`: 设置成功 (由 KBS 返回)。Gateway 会尝试本地存储并记录成功审计。
        
    *   `401 Unauthorized / 403 Forbidden`: 无权限 (由 KBS 返回)。Gateway 记录失败审计。
        
    *   `400 Bad Request`: 请求格式错误 (由 KBS 返回)。Gateway 记录失败审计。
        
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法读取请求体、无法转发请求给 KBS、无法读取 KBS 响应)。响应体通常为 `{"error": "<错误信息>"}`。Gateway 记录失败审计。
        
    *   _其他由 KBS 返回的状态码_。Gateway 记录失败审计。
        
*   **返回示例 (成功 - KBS 返回空内容):**_状态码: 200_ 
    
*   ![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/9b3e85b8-8453-4787-8099-788408fe985c.png)
    

#### 1.11 列出资源 (List Resources)

*   **端点:** `GET /kbs/v0/resources`
    
*   **说明:**  获取**KBS 的资源列表**
    
*   **调用方法:**
    

```shell
# 列出所有资源
curl -k http://<gateway-host>:<port>/api/kbs/v0/resources
# 按仓库过滤
curl -k http://<gateway-host>:<port>/api/kbs/v0/resources?repository=my-repo
# 按类型过滤
curl -k http://<gateway-host>:<port>/api/kbs/v0/resources?type=key
# 按仓库和类型过滤
curl -k http://<gateway-host>:<port>/api/kbs/v0/resources?repository=my-repo&type=key
```

*   **请求头:** 无
    
*   **请求参数:**
    
    *   `repository` (查询参数, string, 可选): 按仓库名过滤。
        
    *   `type` (查询参数, string, 可选): 按资源类型过滤。
        
*   **请求体:** 无
    
*   **响应:**
    
    *   成功时，返回资源 JSON 数组 ，包含 `repository_name`, `resource_type`, `resource_tag`
        
    *   失败时，返回错误信息。
        
*   **返回码:**
    
    *   `200 OK`: 成功。
        
    *   `500 Internal Server Error`: 响应体 `{"error": "Failed to list resources"}`
        
*   **返回示例 (成功):**
    

```json
[
    {
        "repository_name": "123",
        "resource_tag": "123",
        "resource_type": "123"
    },
    {
        "repository_name": "123",
        "resource_tag": "fff",
        "resource_type": "123"
    }
]
```

#### 1.12 删除资源 (Delete Resource)

*   **端点:** `DELETE /kbs/v0/resource/{repository}/{type}/{tag}`
    
*   **说明:** 从 KBS 中删除指定标识的资源。Gateway 会将请求转发给 KBS。如果 KBS 返回成功状态码 (`200 OK`, `204 No Content`)，表示资源删除成功。Gateway 会**异步记录一条资源请求审计日志**。最终将 KBS 的响应返回给客户端。
    
*   **调用方法:**
    

```shell
curl -k -X DELETE http://<gateway-host>:<port>/api/kbs/v0/resource/my-repo/my-type/my-tag  \
     -H "Authorization: Bearer <token>"
```

*   **请求头:**
    
    *   需要 KBS 要求的认证头（生成方法见附录）： `Authorization: Bearer <token>`
        
*   **请求参数:**
    
    *   `repository` (路径参数, string, 必需): 资源所属的仓库名。
        
    *   `type` (路径参数, string, 必需): 资源的类型。
        
    *   `tag` (路径参数, string, 必需): 资源的标签或版本。
        
*   **请求体:** 无
    
*   **响应:**
    
    *   响应体和状态码由后端 KBS 服务决定。
        
    *   无论成功失败，Gateway 都会**异步记录审计日志** (`ResourceRequest`)，包含客户端 IP、会话 ID、资源标识符 (repo, type, tag)、方法 ("DELETE")、KBS 返回的状态码、是否成功 (当 KBS 返回 200 或 204 时为 true) 以及时间戳。
        
*   **返回码:**
    
    *   `200 OK / 204 No Content`: 删除成功 (由 KBS 返回)。Gateway 会记录成功审计。
        
    *   `401 Unauthorized / 403 Forbidden`: 无权限 (由 KBS 返回)。Gateway 记录失败审计。
        
    *   `404 Not Found`: 资源不存在 (由 KBS 返回)。Gateway 记录失败审计。
        
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法转发请求给 KBS、无法读取 KBS 响应)。响应体通常为 `{"error": "<错误信息>"}`。Gateway 记录失败审计。
        
    *   _其他由 KBS 返回的状态码_。Gateway 记录失败审计。
        
*   **返回示例 (成功 - KBS 返回空内容):**_状态码: 200 OK 或 204 No Content_

### ![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/7066c995-d1a1-4d28-b709-013982722a26.png)

---

### AS API (`**/api/attestation-service**`)

这部分 API 用于处理与 Attestation Service (AS) 相关的操作。Gateway 作为代理将请求转发给后端 AS 服务，并将响应返回给客户端。证明操作会异步记录审计日志到 Gateway 数据库。

#### 2.1 证明 (Attestation)

*   **端点:** `POST /attestation-service/attestation`
    
*   **说明:** 用于向后端 AS 服务提交 TEE 证据以进行验证。Gateway 会将请求转发给 AS，并将 AS 的响应返回给客户端。之后，Gateway 会**异步记录一条证明审计日志**到其数据库。
    
*   **调用方法:**
    

```shell
curl -k -X POST http://<gateway-host>:<port>/api/attestation-service/attestation \
     -H 'Content-Type: application/json' \
     -H 'AAInstanceInfo: {"image_id":"aliyun_3_9_x64_20G_uefi_alibase_20231219.vhd","instance_id":"i-bp13wqyr5ik6l669424n","instance_name":"test-cc","owner_account_id":"1242424451954755"}' \
     -d '{
             "verification_requests": [
                 {
                     "tee": "sample",
                     "evidence": "base64_encoded_evidence",
                     "runtime_data": {
                         "structured_runtime_data": "{\"key\": \"value\"}"
                     },
                     "init_data": {
                         "init_data_toml": "algorithm = \"sha384\"..."
                     },
                     "runtime_data_hash_algorithm": "sha384"
                 }
             ],
             "policy_ids": ["default"]
         }'
```

*   **请求头:**
    
    *   `Content-Type: application/json`
        
    *   `AAInstanceInfo: '{"image_id":"aliyun_3_9_x64_20G_uefi_alibase_20231219.vhd","instance_id":"i-bp13wqyr5ik6l669424n","instance_name":"test-cc","owner_account_id":"1242424451954755"}'` (可选，但建议提供)
        
*   **请求体 (JSON - 由 AS 定义):**
    

```json
{
    "verification_requests": [  // (必需) 验证请求数组，支持多个TEE证据
        {
            "tee": "string",     // TEE类型，例如 "sample", "tdx", "sgx"
            "evidence": "string", // Base64编码的证据
            "runtime_data": {    // (可选) 运行时数据
                "raw_runtime_data": "string",        // 原始运行时数据(Base64)
                "structured_runtime_data": "string"  // 结构化运行时数据(JSON字符串)
            },
            "init_data": {       // (可选) 初始化数据
                "init_data_digest": "string",  // 初始化数据摘要(Base64)
                "init_data_toml": "string"     // TOML格式的初始化数据
            },
            "runtime_data_hash_algorithm": "string" // 运行时数据哈希算法，例如 "sha256", "sha384", "sha512"
        }
    ],
    "policy_ids": ["string"]    // (可选) 策略ID数组，如果未提供则使用"default"
}
```


*   **响应:**
    
    *   成功时，响应体、状态码和头由后端 AS 服务决定。
        
        *   通常 AS 返回 `200 OK`。
            
        *   响应体格式由 AS 决定，可能是 JWT 格式的证明令牌或其他格式。
            
    *   失败时，可能由 AS 或 Gateway 返回错误。
        
    *   无论成功失败，Gateway 都会**异步记录审计日志** (`AttestationRecord`)，包含客户端 IP、请求的声明 (claims)、AS 返回的状态码、是否成功 (`仅当 AS 返回 200 时为 true`)、来源服务标识以及时间戳。
        
*   **返回码:**
    
    *   `200 OK`: 证明成功 (由 AS 返回)。
        
    *   `400 Bad Request`: 请求格式错误 (由 AS 返回)。
        
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法读取请求体、无法转发请求给 AS、无法读取 AS 响应)。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他由 AS 返回的状态码 (例如 4xx 证据验证失败, 5xx)_
        
*   **返回示例 (成功 - 返回证明结果):**

```json
{
    "token": "jwt_or_other_format_attestation_result"
}
```

#### 2.2 挑战 (Challenge)

*   **端点:** `POST /attestation-service/challenge`
    
*   **说明:** 用于向后端 AS 服务请求证明挑战。Gateway 会将请求**直接转发**给配置的 AS 服务，并将 AS 的响应返回给客户端。
    
*   **调用方法:**
    

```shell
curl -k -X POST http://<gateway-host>:<port>/api/attestation-service/challenge \
     -H 'Content-Type: application/json' \
     -d '{
             "tee": "tdx",
             "tee_params": "..."
         }'
```

*   **请求头:**
    
    *   `Content-Type: application/json`
        
*   **请求体 (JSON - 由 AS 定义):**
    

```json
{
    "tee": "string",        // (可选) TEE 类型，例如 "tdx", "sgx", "snp"；为空时走通用挑战
    "tee_params": "string" // (可选) 额外参数，传递给特定 TEE 的挑战生成
}
```

*   **响应:** 响应体和状态码由后端 AS 服务决定。
    
*   **返回码:**
    
    *   `200 OK`: 挑战生成成功 (由 AS 返回)。
        
    *   `400 Bad Request`: 请求格式错误 (由 AS 返回)。
        
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法读取请求体、无法转发请求给 AS、无法读取 AS 响应)。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他状态码完全由 AS 决定 (例如 5xx)_。
        
*   **返回示例 (成功):**

```json
{
    "nonce": "base64_encoded_challenge_nonce",
    "extra-params": {
        "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJub25jZSI6IkFiQ0QxMjM0NTYifQ.SIGNATURE"
    }
}
```

> 说明：AS 返回的 `extra-params.jwt` 为一个签名的 JWT，其中包含自定义 claim：`"nonce": "base64_encoded_nonce"`。该 `nonce` 为标准 Base64 编码，供后续 attestation 请求绑定使用。

*   **后续用法（将 ChallengeToken 放入 Attestation 的 runtime_data 中）**

    - 从本接口响应中读取 `extra-params.jwt`（ChallengeToken，JWT 字符串）。
    - 在后续调用 `/attestation-service/attestation` 时，将该 token 放入 `runtime_data` 的结构化 JSON 中，字段名为 `challenge_token`，不再放置于请求头。
    - AS 会验证该 token 的签名与有效期（`exp`，签发端设置为 5 分钟）。仅当 `runtime_data` 中存在 `challenge_token` 且验证失败时，AS 才会直接返回统一错误；若字段不存在或 `runtime_data` 为原始类型，则按原逻辑继续处理。AS 只做验证，不修改来访 `runtime_data` 内容。

```shell
curl -k -X POST http://<gateway-host>:<port>/api/attestation-service/attestation \
     -H 'Content-Type: application/json' \
     -d '{
            "verification_requests": [
                {
                    "tee": "tdx",
                    "evidence": "<base64url_evidence>",
                    "runtime_data": {
                        "structured": {
                            "challenge_token": "<JWT from extra-params.jwt>",
                            "nonce": "base64_encoded_nonce",
                            "tee-pubkey": { "alg": "RSA", "k-mod": "...", "k-exp": "..." }
                        }
                    },
                    "runtime_data_hash_algorithm": "sha384"
                }
            ],
            "policy_ids": ["default"]
        }'
```

*   **错误处理：** 当且仅当 `runtime_data.structured.challenge_token` 存在且验证失败（例如 `400 Bad Request`/`401 Unauthorized`）时，AS 返回统一错误；否则维持原有处理流程。失败原因包括但不限于：
    - 无效的 JWT 结构或 Base64 编码错误
    - 无法读取/解析签名密钥
    - 签名校验失败
    - 缺少 `nonce` claim 或 `nonce` 编码非法

#### 2.3 获取证书 (Get Certificate)

*   **端点:** `GET /attestation-service/certificate`
    
*   **说明:** 用于从后端 AS 服务获取认证证书或证书链。Gateway 会将请求**直接转发**给配置的 AS 服务，并将 AS 的响应返回给客户端。
    
*   **调用方法:**
    

```shell
curl -k http://<gateway-host>:<port>/api/attestation-service/certificate
```

*   **请求头:** 无特殊要求。
    
*   **请求参数:** 无 (具体参数由 AS 定义)。
    
*   **请求体:** 无。
    
*   **响应:** 响应体和状态码由后端 AS 服务决定。
    
    *   成功时 AS 通常返回 `200 OK`，响应体可能是 PEM 格式的证书内容。
        
*   **返回码:**
    
    *   `200 OK`: 成功获取证书 (由 AS 返回)。
        
    *   `404 Not Found`: 证书不存在 (由 AS 返回)。
        
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法转发请求给 AS、无法读取 AS 响应)。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他由 AS 返回的状态码 (例如 5xx)_
        
*   **返回示例 (成功 - 由 AS 返回证书内容):**

```plaintext
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0xNTEyMjkxNTI2NDdaFw0yNTEyMjYxNTI2NDdaMBQxEjAQBgNV
...
-----END CERTIFICATE-----
```

---

### AS API (`**/api/as**`)

这部分 API 是 `/api/attestation-service` 的别名，功能完全相同。用于处理与 Attestation Service (AS) 相关的操作。Gateway 作为代理将请求转发给后端 AS 服务，并将响应返回给客户端。证明操作会异步记录审计日志到 Gateway 数据库。

#### 3.1 证明 (Attestation)

*   **端点:** `POST /as/attestation`
    
*   **说明:** 用于向后端 AS 服务提交 TEE 证据以进行验证。Gateway 会将请求转发给 AS，并将 AS 的响应返回给客户端。之后，Gateway 会**异步记录一条证明审计日志**到其数据库。
    
*   **调用方法:**
    

```shell
curl -k -X POST http://<gateway-host>:<port>/api/as/attestation \
     -H 'Content-Type: application/json' \
     -H 'AAInstanceInfo: {"image_id":"aliyun_3_9_x64_20G_uefi_alibase_20231219.vhd","instance_id":"i-bp13wqyr5ik6l669424n","instance_name":"test-cc","owner_account_id":"1242424451954755"}' \
     -d '{
             "tee-pubkey": {
                 "alg": "RSA",
                 "k-mod": "base64_modulus",
                 "k-exp": "base64_exponent"
             },
             "tee-evidence": { ... }
         }'
```

*   **请求头:**
    
    *   `Content-Type: application/json`
        
    *   `AAInstanceInfo: '{"image_id":"aliyun_3_9_x64_20G_uefi_alibase_20231219.vhd","instance_id":"i-bp13wqyr5ik6l669424n","instance_name":"test-cc","owner_account_id":"1242424451954755"}'` (可选，但建议提供)
        
*   **请求体 (JSON - 由 AS 定义):**
    

```json
{
    "tee-pubkey": {       // (必需) TEE 公钥信息
        "alg": "string",   // 例如 "RSA", "ECDSA"
        "k-mod": "string", // Base64 编码的 RSA 模数 (如果 alg="RSA")
        "k-exp": "string"  // Base64 编码的 RSA 公钥指数 (如果 alg="RSA")
    },
    "tee-evidence": {}     // (必需) TEE 生成的证据 (具体结构取决于 TEE 类型)
}
```

*   **响应:**
    
    *   成功时，响应体、状态码和头由后端 AS 服务决定。
        
        *   通常 AS 返回 `200 OK`。
            
        *   响应体格式由 AS 决定，可能是 JWT 格式的证明令牌或其他格式。
            
    *   失败时，可能由 AS 或 Gateway 返回错误。
        
    *   无论成功失败，Gateway 都会**异步记录审计日志** (`AttestationRecord`)，包含客户端 IP、请求的声明 (claims)、AS 返回的状态码、是否成功 (`仅当 AS 返回 200 时为 true`)、来源服务标识以及时间戳。
        
*   **返回码:**
    
    *   `200 OK`: 证明成功 (由 AS 返回)。
        
    *   `400 Bad Request`: 请求格式错误 (由 AS 返回)。
        
    *   `500 Internal Server Error`: Gateway 内部错误 (例如，无法读取请求体、无法转发请求给 AS、无法读取 AS 响应)。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他由 AS 返回的状态码 (例如 4xx 证据验证失败, 5xx)_
        
*   **返回示例 (成功 - 返回证明结果):**

```json
{
    "token": "jwt_or_other_format_attestation_result"
}
```

#### 3.2 挑战 (Challenge)

*   **端点:** `POST /as/challenge`
    
*   **说明:** 用于向后端 AS 服务请求证明挑战。Gateway 会将请求**直接转发**给配置的 AS 服务，并将 AS 的响应返回给客户端。
    
*   **调用方法:**
    

```shell
curl -k -X POST http://<gateway-host>:<port>/api/as/challenge \
     -H 'Content-Type: application/json' \
     -d '{
             "tee": "tdx",
             "extra-params": "..."
         }'
```

*   **请求头:**
    
    *   `Content-Type: application/json`
        
*   **请求体 (JSON - 由 AS 定义):**
    

```json
{
    "tee": "string",        // (必需) TEE 类型，例如 "tdx", "tpm", "csv"
    "extra-params": "string" // (可选) 额外参数
}
```

*   **响应:**
    
    *   成功时，响应体、状态码和头由后端 AS 服务决定。
        
    *   失败时，可能由 AS 或 Gateway 返回错误。
        
*   **返回码:**
    
    *   `200 OK`: 挑战生成成功 (由 AS 返回)。
        
    *   `400 Bad Request`: 请求格式错误 (由 AS 返回)。
        
    *   `500 Internal Server Error`: Gateway 内部错误。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他由 AS 返回的状态码_
        
*   **返回示例 (成功 - 由 AS 返回挑战):**

```json
{
    "challenge": "base64_encoded_challenge_data"
}
```

#### 3.3 获取证书 (Get Certificate)

*   **端点:** `GET /as/certificate`
    
*   **说明:** 用于从后端 AS 服务获取证书。Gateway 会将请求**直接转发**给配置的 AS 服务，并将 AS 的响应返回给客户端。
    
*   **调用方法:**
    

```shell
curl -k http://<gateway-host>:<port>/api/as/certificate
```

*   **请求头:** 无特殊要求。
    
*   **请求参数:** 无。
    
*   **请求体:** 无。
    
*   **响应:**
    
    *   成功时，响应体、状态码和头由后端 AS 服务决定。
        
        *   通常 AS 返回 `200 OK`。
            
        *   响应体通常是证书内容，`Content-Type` 可能是 `application/x-pem-file` 或其他格式。
            
    *   失败时，可能由 AS 或 Gateway 返回错误。
        
*   **返回码:**
    
    *   `200 OK`: 获取证书成功 (由 AS 返回)。
        
    *   `404 Not Found`: 证书不存在 (由 AS 返回)。
        
    *   `500 Internal Server Error`: Gateway 内部错误。响应体通常为 `{"error": "<错误信息>"}`。
        
    *   _其他由 AS 返回的状态码_
        
*   **返回示例 (成功 - 由 AS 返回证书内容):**

```plaintext
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0xNTEyMjkxNTI2NDdaFw0yNTEyMjYxNTI2NDdaMBQxEjAQBgNV
...
-----END CERTIFICATE-----
```

---

### RVPS API (`**/api/rvps**`)

这部分 API 用于与参考值提供服务 (Reference Value Provider Service - RVPS) 进行交互。Gateway 仅在配置了 RVPS gRPC 客户端的情况下处理这些请求，否则将返回 404。

#### 4.1 查询参考值 (Query Reference Value)

*   **端点:** `GET /api/rvps/query`
    
*   **说明:** 通过 gRPC 向后端 RVPS 服务查询参考值。
    
*   **调用方法:**
    

```shell
curl -k http://<gateway-host>:<port>/api/rvps/query
```

*   **请求头:** 无特殊要求。
    
*   **请求参数:** 无 (HTTP 请求参数不传递给 gRPC 调用)。
    
*   **请求体:** 无。
    
*   **响应:**
    
    *   成功时，返回 RVPS gRPC 服务返回的**字符串**结果，`Content-Type` 设置为 `application/json`。
        
    *   失败时，返回错误信息。
        
*   **返回码:**
    
    *   `200 OK`: 查询成功。响应体是来自 RVPS 的 JSON 字符串。
        
    *   `500 Internal Server Error`: 调用 RVPS gRPC 失败。响应体 `{"error": "<gRPC 错误信息>"}`。
        
    *   `404 Not Found`: 如果 Gateway 未配置 RVPS gRPC 客户端。
        
*   **返回示例 (成功):**_状态码: 200 OK响应头:_ `_Content-Type: application/json_`_响应体 (来自 RVPS 的原始字符串):_
    

```json
{
    "test-binary-100": [
        "reference-value-3",
        "reference-value-99"
    ],
    "test-binary-2": [
        "reference-value-3",
        "reference-va"
    ],
    "test-binary-1": [
        "reference-value-1",
        "reference-value-2"
    ]
}
```

![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/ad6f5cea-87c0-4e21-a85d-ab1b3314e969.png)

#### 4.2 注册参考值 (Register Reference Value)

*   **端点:** `POST /api/rvps/register`
    
*   **说明:** 通过 gRPC 向后端 RVPS 服务注册参考值。
    
*   **调用方法:**
    

```shell
# 要注册的参考值信息作为 JSON 字符串嵌套在 message 字段中
#rvps.json:
{"message":"{\"version\":\"0.1.0\",\"type\":\"sample\",\"payload\":\"ewogICAgInRlc3QtYmluYXJ5LTEiOiBbCiAgICAgICAgInJlZmVyZW5jZS12YWx1ZS0xIiwKICAgICAgICAicmVmZXJlbmNlLXZhbHVlLTIiCiAgICBdLAogICAgInRlc3QtYmluYXJ5LTIiOiBbCiAgICAgICAgInJlZmVyZW5jZS12YWx1ZS0zIiwKICAgICAgICAicmVmZXJlbmNlLXZhbHVlLTQiCiAgICBdCn0K\"}"}

curl -k -X POST http://<gateway-host>:<port>/api/rvps/register \
     -H 'Content-Type: application/json' \
     -d @rvps.json
```

*   **请求头:**
    
    *   `Content-Type: application/json`
        
*   **请求参数:** 无。
    
*   **请求体 (JSON):**
    

```json
{
    "message": "string" // (必需) 需要传递给 RVPS gRPC 接口的参考值信息字符串。
}
```

请求体中message的格式当前仅支持如下一种（后续会新增多种支持的参考值格式）：

```json
cat << EOF > sample
{
    "test-binary-1": [
        "reference-value-1",
        "reference-value-2"
    ],
    "test-binary-2": [
        "reference-value-3",
        "reference-value-4"
    ]
}
EOF

provenance=$(cat sample | base64 --wrap=0)

cat << EOF > message
{
    "version" : "0.1.0",
    "type": "sample",
    "payload": "$provenance"
}
EOF
```

*   **响应:**
    
    *   成功时，返回空响应体。
        
    *   失败时，返回错误信息。
        
*   **返回码:**
    
    *   `200 OK`: 注册成功 (gRPC 调用成功)。
        
    *   `400 Bad Request`: 请求体无法读取或解析为包含 `message` 字段的 JSON。响应体 `{"error": "Failed to read request body"}` 或 `{"error": "Invalid request format"}`。
        
    *   `500 Internal Server Error`: 调用 RVPS gRPC 失败。响应体 `{"error": "<gRPC 错误信息>"}`。
        
    *   `404 Not Found`: 如果 Gateway 未配置 RVPS gRPC 客户端。
        
*   **返回示例 (成功):**_状态码: 200 OK响应体: (空)_
    

![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/22b4361d-9b13-487a-bcb7-b0acee409517.png)

#### 4.3 删除参考值 (Delete Reference Value)

*   **端点:** `DELETE /api/rvps/delete/{name}`
    
*   **说明:** 通过 gRPC 向后端 RVPS 服务删除指定名称的参考值。
    
*   **调用方法:**
    

```shell
# 删除名为 "test-binary-1" 的参考值
curl -k -X DELETE http://<gateway-host>:<port>/api/rvps/delete/test-binary-1
```

*   **请求头:** 无特殊要求。
    
*   **请求参数:** 
    *   `name` (路径参数): 要删除的参考值名称
    
*   **请求体:** 无。
    
*   **响应:**
    
    *   成功时，返回空响应体。
        
    *   失败时，返回错误信息。
        
*   **返回码:**
    
    *   `200 OK`: 删除成功 (gRPC 调用成功)。
        
    *   `400 Bad Request`: 参考值名称为空。响应体 `{"error": "Reference value name is required"}`。
        
    *   `500 Internal Server Error`: 调用 RVPS gRPC 失败。响应体 `{"error": "<gRPC 错误信息>"}`。
        
    *   `404 Not Found`: 如果 Gateway 未配置 RVPS gRPC 客户端。
        
*   **返回示例 (成功):**_状态码: 200 OK响应体: (空)_

### 审计 API (`**/api/audit**`)

这部分 API 用于查询 **Gateway 数据库中**记录的审计日志。

#### 5.1 列出认证记录 (List Attestation Records)

*   **端点:** `GET /api/audit/attestation`
    
*   **说明:** 查询 `/api/kbs/v0/attest` 和 `/api/attestation-service/attestation` 端点的调用记录 (存储在 Gateway 数据库中)。
    
*   **调用方法:**
    

```shell
# 查询所有记录 (默认 limit=100, offset=0)
curl -k http://<gateway-host>:<port>/api/audit/attestation
# 按 session_id 过滤
curl -k http://<gateway-host>:<port>/api/audit/attestation?session_id=your-session-id
# 按来源服务过滤
curl -k http://<gateway-host>:<port>/api/audit/attestation?source_service=kbs
# 按 AA 实例 ID 过滤
curl -k http://<gateway-host>:<port>/api/audit/attestation?instance_id=i-12345
# 查询成功的记录 (基于 KBS 返回的状态码是否为 200)
curl -k http://<gateway-host>:<port>/api/audit/attestation?successful=true
# 查询某个时间段的记录 (RFC3339 格式)
curl -k http://<gateway-host>:<port>/api/audit/attestation?start_time=2024-01-01T00:00:00Z&end_time=2024-01-31T23:59:59Z
# 分页查询 (第 2 页，每页 50 条)
curl -k http://<gateway-host>:<port>/api/audit/attestation?limit=50&offset=50
```

*   **请求参数:**
    
    *   `session_id` (查询参数, string, 可选): 按 KBS 会话 ID 过滤。
        
    *   `source_service` (查询参数, string, 可选): 按来源服务过滤 (例如 "kbs", "attestation-service")。
        
    *   `instance_id` (查询参数, string, 可选): 按 AA 实例 ID 过滤。
        
    *   `successful` (查询参数, boolean, 可选): 按请求是否成功过滤 (`true` 或 `false`)。无效值将被忽略。
        
    *   `start_time` (查询参数, string, 可选): 按时间范围过滤 (开始时间，RFC3339 格式)。无效格式将被忽略。
        
    *   `end_time` (查询参数, string, 可选): 按时间范围过滤 (结束时间，RFC3339 格式)。无效格式将被忽略。
        
    *   `limit` (查询参数, integer, 可选, 默认 100): 返回记录的最大数量。无效或非正数默认为 100。
        
    *   `offset` (查询参数, integer, 可选, 默认 0): 返回记录的起始偏移量。无效或负数默认为 0。
        
*   **响应:**
    
    *   成功时，返回包含认证记录列表和总数的 JSON 对象，包含 `data` (记录数组) 和 `total` (满足筛选条件的总记录数，独立于本次分页返回数量)。
    
    *   失败时，返回错误信息。
        
*   **返回码:**
    
    *   `200 OK`: 成功。
        
    *   `500 Internal Server Error`: 查询 Gateway 数据库出错。响应体 `{"error": "Failed to list attestation records"}`。
        
*   **返回示例 (成功):**
    

```json
{
    "data": [
        {
            "id": 1,
            "client_ip": "192.168.1.101",
            "session_id": "session-abc",
            "request_body": "{\"tee-pubkey\":{...},\"tee-evidence\":{...}}",
            "claims": "{\"customized_claims\":{\"init_data\":null,\"runtime_data\":{\"nonce\":\"DfnnB6Geop0ymdqQQg88oR+hjNKe7NzWIqzssBqdVe0=\",\"tee-pubkey\":{\"alg\":\"RSA1_5\",\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"uOoYePWev5VF9uUzHlkED6MB-n5bS-iCoIIoBJsfEqYt9mHda-mhN0iPK91gYcC33ilHWDaGqMveevsJ9n8-e-qgu3r4-SpMdURxsuQY8RmUjxcStFhfH56ZEaziASyVi9G94kBIpS3ApOIMf-oOdgoOft2eCYnMzuY0dplQKNGS6rB_78SD9F0gaMQ_Q0JaxlXKXK8OhiaoFOjFMlVtEnrk5FI_WsWWMOitinBT9jng-JRRqCHihicF16_iAmktPPEn3MeY6NiLDxNhoQYw-72u_nhdfMwO2KXsjUwFTF_06wTeiGfiqNcR1sRco_H8_X-iFbZS4DZxxBos5KWHuQ\"}}},\"evaluation-reports\":[{\"policy-hash\":\"f5abdc02716d85a5ab28cf43500201591bbe4e5600751039462e5ec2e0ae2698d637c1f487f58bca182244eefdf3b4b1\",\"policy-id\":\"default\"}],\"exp\":1752589512,\"iat\":1752589212,\"iss\":\"CoCo-Attestation-Service\",\"jti\":\"BDbHikXUMj\",\"nbf\":1752589212,\"tcb-status\":\"{\\\"init_data\\\":\\\"\\\",\\\"report_data\\\":\\\"zQU7fRqrb5gE+NLN0bVOWkYZGZvNzTIkStwALFtpX5wawbYY4J6CCV7PC2TvfFFn\\\",\\\"sample.svn\\\":\\\"1\\\"}\",\"tee\":\"sample\"}",
            "status": 200,
            "successful": true,
            "timestamp": "2024-01-10T12:34:56Z",
            "source_service": "kbs",
            "instance_id": "i-12345",
            "image_id": "img-abc",
            "instance_name": "my-instance",
            "owner_account_id": "123456789"
        },
        {
            "id": 2,
            "client_ip": "10.0.0.5",
            "session_id": "session-xyz",
            "request_body": "",
            "claims": "{\"tee-pubkey\":{...},\"tee-evidence\":{...}}",
            "status": 403,
            "successful": false,
            "timestamp": "2024-01-10T12:35:10Z",
            "source_service": "attestation-service",
            "instance_id": "i-67890",
            "image_id": "img-def",
            "instance_name": "another-instance",
            "owner_account_id": "987654321"
        }
    ],
    "total": 2
}
```

![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/1a9e39fe-2b91-4d75-a0f2-f54d1967ea40.png)

#### 5.2 列出资源请求记录 (List Resource Requests)

*   **端点:** `GET /api/audit/resources`
    
*   **说明:** 查询 `/api/kbs/v0/resource/{repository}/{type}/{tag}` (GET 和 POST) 端点的调用记录 (存储在 Gateway 数据库中)。
    
*   **调用方法:**
    

```shell
# 查询所有记录
curl -k http://<gateway-host>:<port>/api/audit/resources
# 按仓库和类型过滤
curl -k http://<gateway-host>:<port>/api/audit/resources?repository=my-repo&type=key
# 按方法过滤 (GET 请求)
curl -k http://<gateway-host>:<port>/api/audit/resources?method=GET
# 按 AA 实例 ID 过滤
curl -k http://<gateway-host>:<port>/api/audit/resources?instance_id=i-12345
# 查询失败的 POST 请求 (基于 KBS 返回的状态码)
curl -k http://<gateway-host>:<port>/api/audit/resources?method=POST&successful=false
# 其他参数同 /audit/attestation (session_id, tag, start_time, end_time, limit, offset)
```

*   **请求参数:**
    
    *   `session_id` (查询参数, string, 可选): 按 KBS 会话 ID 过滤。
        
    *   `repository` (查询参数, string, 可选): 按资源仓库名过滤。
        
    *   `type` (查询参数, string, 可选): 按资源类型过滤。
        
    *   `tag` (查询参数, string, 可选): 按资源标签过滤。
        
    *   `method` (查询参数, string, 可选): 按 HTTP 方法过滤 (e.g., "GET", "POST")。
        
    *   `instance_id` (查询参数, string, 可选): 按 AA 实例 ID 过滤。
        
    *   `successful` (查询参数, boolean, 可选): 按请求是否成功过滤 (`true` 或 `false`)。
        
        *   对于 GET，成功意味着 KBS 返回 200。
            
        *   对于 POST，成功意味着 KBS 返回 200, 201 或 204。
            
        *   无效值将被忽略。
            
    *   `start_time` (查询参数, string, 可选): 按时间范围过滤 (开始时间，RFC3339 格式)。无效格式将被忽略。
        
    *   `end_time` (查询参数, string, 可选): 按时间范围过滤 (结束时间，RFC3339 格式)。无效格式将被忽略。
        
    *   `limit` (查询参数, integer, 可选, 默认 100): 返回记录的最大数量。无效或非正数默认为 100。
        
    *   `offset` (查询参数, integer, 可选, 默认 0): 返回记录的起始偏移量。无效或负数默认为 0。
        
*   **请求体:** 无。
    
*   **响应:**
    
    *   成功时，返回包含资源请求记录列表和总数的 JSON 对象，包含 `data` (记录数组) 和 `total` (满足筛选条件的总记录数，独立于本次分页返回数量)。
    
    *   失败时，返回错误信息。
        
*   **返回码:**
    
    *   `200 OK`: 成功。
        
    *   `500 Internal Server Error`: 查询 Gateway 数据库出错。响应体 `{"error": "Failed to list resource requests"}`。
        
*   **返回示例 (成功):**
    

```json
{
    "data": [
        {
            "id": 1,
            "client_ip": "192.168.1.102",
            "session_id": "session-def",
            "repository": "my-repo",
            "type": "key",
            "tag": "latest",
            "method": "GET",
            "status": 200,
            "successful": true,
            "timestamp": "2024-01-11T09:15:00Z",
            "instance_id": "i-abcde",
            "image_id": "img-123",
            "instance_name": "resource-getter",
            "owner_account_id": "1122334455"
        },
        {
            "id": 2,
            "client_ip": "10.0.0.6",
            "session_id": "",
            "repository": "my-repo",
            "type": "config",
            "tag": "prod",
            "method": "POST",
            "status": 201,
            "successful": true,
            "timestamp": "2024-01-11T09:20:00Z",
            "instance_id": "i-fghij",
            "image_id": "img-456",
            "instance_name": "resource-setter",
            "owner_account_id": "6677889900"
        },
        {
            "id": 3,
            "client_ip": "10.0.0.7",
            "session_id": "",
            "repository": "my-repo",
            "type": "data",
            "tag": "v1",
            "method": "GET",
            "status": 404,
            "successful": false,
            "timestamp": "2024-01-11T09:25:00Z",
            "instance_id": "i-klmno",
            "image_id": "img-789",
            "instance_name": "resource-failed",
            "owner_account_id": "123123123"
        }
    ],
    "total": 3
}
```

![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/e8d72305-e3ba-423e-ae65-ead7d7c9e252.png)

### 6. 健康检查 API (`**/api**`)

#### 6.1 基本健康检查

*   **端点:** `GET /api/health`
    
*   **说明:** 提供一个简单的健康检查端点，确认 Gateway 服务本身正在运行。
    
*   **调用方法:**
    

```shell
curl -k http://<gateway-host>:<port>/api/health
```

*   **请求头:** 无。
    
*   **请求参数:** 无。
    
*   **请求体:** 无。
    
*   **响应:** 返回一个简单的 JSON 对象。
    
*   **返回码:**
    
    *   `200 OK`: 服务运行正常。
        
*   **返回示例 (成功):**
    

```json
{
    "status": "ok"
}
```

![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/a9973c16-7a40-49d4-a011-da007cc3c555.png)

#### 6.2 服务健康检查

*   **端点:** `GET /api/services-health`
    
*   **说明:** 检查 Gateway 自身以及其依赖的后端服务 (KBS, RVPS) 的健康状况。**注意：此端点总是返回 200 OK，实际健康状态在响应体中指示。**
    
*   **调用方法:**
    

```shell
curl -k http://<gateway-host>:<port>/api/services-health
```

*   **请求头:** 无。
    
*   **请求参数:** 无。
    
*   **请求体:** 无。
    
*   **响应:** 返回一个包含各服务健康状态的 JSON 对象 (`HealthStatus` 结构)。
    
    *   `gateway`: 始终报告 `"ok"`。
        
    *   `kbs`: 通过向 KBS 发送一个实际的 `/auth` 请求 (`tee: "sample"`) 来检查。可能的状态: `"ok"` 或 `"error"` (附带 `message`)。
        
    *   `rvps`: 始终报告 `"not supported"` (当前未实现实际检查)。
        
*   **返回码:**
    
    *   `200 OK`: 总是返回此状态码，即使后端服务检查失败。
        
*   **返回示例** 
    

```json
{
    "gateway": {
        "status": "ok",
        "timestamp": "2024-01-12T10:30:00Z"
    },
    "kbs": {
        "status": "ok",
        "timestamp": "2024-01-12T10:30:00Z"
    },
    "rvps": {
        "status": "not supported",
        "timestamp": "2024-01-12T10:30:00Z"
    }
}
```

*   **返回示例 (KBS 检查失败):**
    

```plaintext
{    "gateway": {        "status": "ok",        "timestamp": "2024-01-12T10:35:00Z"    },    "kbs": {        "status": "error",        "message": "forward kbs auth request failed", // 可能的消息: "create kbs auth request failed", "forward kbs auth request failed", "kbs auth request failed"        "timestamp": "2024-01-12T10:35:00Z"    },    "rvps": {        "status": "not supported",        "timestamp": "2024-01-12T10:35:00Z"    }}
```

![image.png](https://alidocs.oss-cn-zhangjiakou.aliyuncs.com/res/2M9qP57A13dzpO01/img/6d64d513-4484-4048-b042-59588a420f67.png)

### 7. 实例API (`**/api/aa-instance**`)

#### 7.1 AA实例心跳

*   **端点:** `POST /api/aa-instance/heartbeat`
    
*   **说明:** 提供一个简单的心跳端点，确认AA实例正在运行。
    
*   **调用方法:**
    

```shell
curl -X POST http://<gateway-host>:<port>/api/aa-instance/heartbeat \
  -H "AAInstanceInfo: {\"instance_id\":\"test-instance-153\",\"image_id\":\"test-image\",\"instance_name\":\"test-instance\",\"owner_account_id\":\"test-account\"}"
```

*   **请求头:** 
    

*   `AAInstanceInfo: '{"image_id":"aliyun_3_9_x64_20G_uefi_alibase_20231219.vhd","instance_id":"i-bp13wqyr5ik6l669424n","instance_name":"test-cc","owner_account_id":"1242424451954755"}'` 
    

*   **请求参数:** 无。
    
*   **请求体:** 无。
    
*   **响应:** 返回一个简单的 JSON 对象。
    
*   **返回码:**
    
    *   `200 OK`: 服务运行正常。
        
*   **返回示例 (成功):**
    

```json
{"status":"ok","timestamp":"2025-06-10T11:58:42+08:00"}
```

#### 7.2 实例列表

*   **端点:** `GET /api/aa-instance/list`
    
*   **说明:** 列出当前在心跳过期时间内的aa实例
    
*   **调用方法:**
    

```shell
curl -k http://<gateway-host>:<port>/api/aa-instance/list
```

*   **请求头:** 无。
    
*   **请求参数:** 无。
    
*   **请求体:** 无。
    
*   **响应:** 返回当前活跃AA实例列表。
    
*   **返回码:**
    
    *   `200 OK`: 服务运行正常。
        
*   **返回示例 (成功):**
    

```json
{
  "active_aa_instances": [
    {
      "ID": 1,
      "CreatedAt": "2025-06-10T11:48:28.393004038+08:00",
      "UpdatedAt": "2025-06-10T11:58:42.784923152+08:00",
      "DeletedAt": null,
      "instance_id": "i-bp13wqyr5ik6l669424n",
      "image_id": "aliyun_3_9_x64_20G_uefi_alibase_20231219.vhd",
      "instance_name": "qianyue-activatepro",
      "owner_account_id": "1242424451954755",
      "client_ip": "::1",
      "last_heartbeat": "2025-06-10T11:58:42.784737526+08:00"
    }
  ],
  "count": 1,
  "timestamp": "2025-06-10T11:58:44+08:00"
}
```

# 附录

## KBS认证头生成方法

当trustee的管理员需要对涉及到机密数据（KBS语义下称为Resource）和证明策略的内容进行配置和操作时，调用相关API需要一个被kbs认证密钥签名的JWT格式令牌来认证请求者身份。

kbs认证密钥为一个ED25519算法的PEM格式私钥文件，在Trustee实例部署时生成，需要导出并妥善保存。

下面提供了一个简单的Python脚本，用于生成KBS认证头令牌，用法如下：

```shell
pip install pyjwt cryptography
python kbs_auth_token.py /path/to/kbs-auth-private.key
```

脚本内容如下 (kbs_auth_token.py)：

```python
import sys, datetime
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def sign_jwt(key_path):
    with open(key_path, 'rb') as f: key = load_pem_private_key(f.read(), None)
    now = datetime.datetime.now(datetime.timezone.utc)
    token = jwt.encode(
        {
            'iat': int(now.timestamp()),
            'exp': int((now + datetime.timedelta(hours=2)).timestamp()),
        },
        key,
        algorithm='EdDSA',
    )
    # PyJWT 1.x returns bytes; 2.x returns str
    return token.decode('utf-8') if isinstance(token, (bytes, bytearray)) else token

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python kbs_auth_token.py <private_key>')
        sys.exit(1)
    try:
        print(sign_jwt(sys.argv[1]))
    except Exception as e:
        print(f'Error: {e}')
        sys.exit(1)
```