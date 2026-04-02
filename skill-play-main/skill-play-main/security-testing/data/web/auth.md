# 认证漏洞

## 1. 认证绕过

### SQL注入绕过

```
admin'--
admin' or '1'='1
```

### 空密码绕过

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

## 2. 会话劫持

### Cookie窃取

```javascript
document.cookie
```

### Session fixation

```
攻击者设置用户的Session ID
```

### Session预测

---

## 3. 密码重置漏洞

### Token可预测

```
重置链接: http://target.com/reset?token=12345
```

### Token泄露

- Referer泄露
- 邮件泄露

### Token复用

### 邮箱绑定漏洞

---

## 4. OAuth漏洞

### redirect_uri绕过

```
正常: http://target.com/callback
绕过: http://target.com.attacker.com
```

### state参数缺失

### 权限绕过

### token泄露

---

## 5. SAML漏洞

### XML签名绕过

### SAML重放

### 断言注入

---

## 6. 2FA绕过

### 2FA码暴力破解

### 2FA码复用

### 绕过2FA

```
直接访问受保护资源
```

### 备份码利用

---

## 7. 验证码绕过

### 验证码复用

### 验证码可预测

### 验证码删除

### 验证码IDOR

---

## 8. 记住我漏洞

```javascript
// 伪造remember me cookie
```

## 9. 暴力破解

### 速率限制绕过

```
X-Forwarded-IP
X-Real-IP
```
