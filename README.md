# Trustee

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Fkbs.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Fkbs?ref=badge_shield)

Trustee是一个用于机密计算（Confidential Computing）TEE (Trust Execute Evironment)环境中的信任验证和秘密数据管理平台。它包含了一系列组件，用于验证可信执行环境（TEE）证据并为其提供秘密数据。该项目遵循RATS（Remote Attestation Procedures）架构模型，为机密容器和其他机密计算应用场景提供完整的信任基础设施。
Trustee 通常代表TEE所有者操作，并与 [guest-components](https://github.com/inclavare-containers/guest-components) 远程交互。

Trustee 可以广泛应用于多种应用程序和硬件平台。

## 组件

- [Key Broker Service](kbs)
  用于协助远程证明和机密数据下发。其角色类似于 RATS 模型中的 [Rely Party](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html#name-relying-party)。

- [Attestation Service](attestation-service)
  用于验证 TEE 证据。在 RATS 模型中，这是 [Verfier](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html#name-verifier)。

- [参考值提供服务 (RVPS)](rvps)
  RVPS 管理用于验证 TEE 证据的参考值。这与 RATS 文档中 [第 7.5 节](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html#name-endorser-reference-value-pr) 的讨论相关。

- [KBS 客户端工具](tools/kbs-client/)
  一个简单的客户端工具，可用于测试或配置 KBS 和 AS，一些场合下又称作Trustee Client。

Trustee项目采用微服务架构，主要包含以下核心模块组件：

### 服务层组件

- [Key Broker Service](kbs): 密钥代理服务，用于协助远程证明和机密数据下发。其角色类似于 RATS 模型中的 [Rely Party](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html#name-relying-party)。

- [Attestation Service](attestation-service): 证明服务，用于验证 TEE 证据。在 RATS 模型中，充当RATS模型中的 [Verfier](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html#name-verifier)。

- [Reference Value Provider Service](rvps): 参考值提供服务，管理用于验证 TEE 证据的参考值。这与 RATS 文档中 [第 7.5 节](https://www.ietf.org/archive/id/draft-ietf-rats-architecture-22.html#name-endorser-reference-value-pr) 的讨论相关。

- [Trustee Gateway](trustee-gateway): API网关，提供统一的接入点和代理服务。

### 远程证明验证插件

- [Verifier](deps/verifier/): 多TEE硬件和设备验证器，支持Intel TDX、Intel SGX、AMD SNP、ARM CCA、Hygon CSV、TPM等

### 支撑组件

- [Frontend](frontend/) React前端管理界面

更多详细信息，请参阅各个组件的文档。

## 架构

下图展示了将Trustee服务组件与客户端组件结合部署时的全局架构。

```mermaid
graph TB
    subgraph "客户端 Guest Environment"
        AA[Attestation Agent]
        CDH[Confidential Data Hub]
        AA <--> CDH
    end

    subgraph "Trustee Gateway Layer"
        GW[Trustee Gateway<br/>统一接入网关]
        FE[Frontend<br/>管理界面]
        FE --> GW
    end

    subgraph "Trustee Core Services"
        KBS[KBS<br/>Key Broker Service]
        AS[AS<br/>Attestation Service]
        RVPS[RVPS<br/>Reference Value Provider Service]
        
        KBS --> AS
        AS --> RVPS
    end

    subgraph "Verifier Engines"
        VER[Verifier<br/>多TEE验证器]
        TDX[TDX Verifier]
        SGX[SGX Verifier]  
        SNP[SNP Verifier]
        CCA[CCA Verifier]
        CSV[CSV Verifier]
        TPM[TPM Verifier]
        
        VER --> TDX
        VER --> SGX
        VER --> SNP
        VER --> CCA
        VER --> CSV
        VER --> TPM
    end

    subgraph "Storage & Policy"
        DB[(Database<br/>SQLite)]
        FS[("File Storage<br/>Reference Values")]
        PE[Policy Engine<br/>OPA]
    end

    AA --证明请求--> GW
    CDH --资源请求--> GW
    GW --> KBS
    GW --> AS
    GW --> RVPS
    
    AS --> VER
    AS --> PE
    RVPS --> FS
    GW --> DB
    
    style KBS fill:#e1f5fe
    style AS fill:#f3e5f5
    style RVPS fill:#e8f5e8
    style GW fill:#fff3e0
    style VER fill:#fce4ec
```

## 构建

使用如下命令，在本地构建Trustee组件的容器镜像：

```shell
DOCKER_BUILDKIT=1 docker build -t kbs:latest . -f Dockerfile.kbs
DOCKER_BUILDKIT=1 docker build -t as-grpc:latest . -f Dockerfile.as-grpc
DOCKER_BUILDKIT=1 docker build -t as-restful:latest . -f Dockerfile.as-restful
DOCKER_BUILDKIT=1 docker build -t rvps:latest . -f Dockerfile.rvps
DOCKER_BUILDKIT=1 docker build -t trustee-gateway:latest . -f Dockerfile.trustee-gateway
DOCKER_BUILDKIT=1 docker build -t frontend:latest . -f Dockerfile.frontend
```

## 部署

### Docker Compose

本仓库提供了docker compose脚本，用于一键在本地启动一个Trustee服务。

脚本中默认使用的组件容器镜像是我们发布在阿里云ACR镜像仓库上的镜像，若您需要使用自己构建的容器镜像，请修改docker compose脚本中每个容器的`image`字段为您自己的容器镜像地址。

使用如下命令在本地一键拉起trustee服务：

```shell
git clone https://github.com/openanolis/trustee.git
cd trustee/deploy
./pre.sh
docker-compose up -d
```

部署完成后，Trustee会在本地监听`8082`端口，接受并处理对 gateway API 和前端访问的请求。

- API: `http://<ip>:8082/api` 
- 前端: `http://<ip>:8082` 

可以使用如下命令测试API访问：

```shell
curl http://<IP>:8082/api/services-health | jq
```

预期输出如下：

```shell
{
  "gateway": {
    "status": "ok",
    "timestamp": "2025-07-02T15:35:55+08:00"
  },
  "kbs": {
    "status": "ok",
    "timestamp": "2025-07-02T15:35:55+08:00"
  },
  "as": {
    "status": "ok",
    "timestamp": "2025-07-02T15:35:55+08:00"
  },
  "rvps": {
    "status": "ok",
    "timestamp": "2025-07-02T15:35:55+08:00"
  }
}
```

### 配置HTTPS：

首先需要自行申请一个有效的SSL证书，然后修改`deploy/trustee-frontend.conf`文件：

```nginx
server {
    listen       8082 ssl; # 此处添加ssl声明
    server_name  localhost;
    # ...
    
    # SSL配置
    ssl_certificate     /path/to/ssl.crt; # 配置SSL证书路径
    ssl_certificate_key /path/to/ssl.key; # 配置SSL密钥路径
    
    # ...其余内容省略
} 
```

保存后重启Trustee服务：

```shell
docker compose restart
```

## 登陆

部署完成后，使用如下命令获得管理员登陆密钥：

```shell
cat deploy/kbs-private.key
```

预期输出：

```shell
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2**********************7QaInHD49zHYNQTaX
-----END PRIVATE KEY-----
```

浏览器打开地址`http://<ip>:8082`, 在登陆界面粘贴上述密钥，点击登录按钮：

![Trustee 登录界面](images/trustee-login.png)

进入Trustee控制台：

![Trustee 控制台](images/trustee-web.png)

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Fkbs.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Fkbs?ref=badge_large)







