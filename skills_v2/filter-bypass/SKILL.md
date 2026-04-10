---
name: filter-bypass
description: Use when encountering Java Filter 权限绕过 - URI 非标准化、URL 截断、URL 编码绕过
---

# Java Filter 权限绕过

## Info

- **Tags**: java, filter, bypass, authorization
- **场景**: 访问控制绕过、权限提升、未授权访问

---

## 1. 原理

Java Web 应用常用 Filter 做权限校验，通过 `request.getRequestURI()` / `request.getRequestURL()` 获取当前路径进行匹配。如果 Filter 和实际中间件对 URI 的解析不一致，就会产生绕过。

---

## 2. 非标准化绕过

### 场景

`/system/login` 开头是白名单（无需登录），其他路径需要鉴权。

### 绕过

```
GET /login/../../admin/UserSearch.do
```

`getRequestURI()` 不进行 `../` 规范化，Filter 认为匹配 `/system/login` 白名单，但实际中间件会解析 `../` 跳转到其他路径。

---

## 3. URL 截断绕过（分号 `;`）

### 场景

Filter 使用 `endsWith()` 或正则匹配 URI，防止 `../` 绕过。

### 绕过

URL 中 `;` 是参数分隔符，不影响实际路由：

```
GET /system;Bypass/UserSearch.do;Bypass
```

Filter 拿到的是带 `;Bypass` 的 URI，绕过了 `endsWith()` 检测，但 Tomcat 仍能正确路由到 `/system/UserSearch.do`。

---

## 4. URL 编码绕过

### 场景

Filter 通过 `getRequestURI()` 获取原始编码路径，不做解码就进行匹配。

### 绕过

```
GET /system/%55%73%65%72%49%6e%66%6f%53%65%61%72%63%68%2e%64%6f
```

Filter 拿到的是编码后的字符串，无法匹配 `/system/UserInfoSearch.do`，但 Tomcat 会解码后正常路由。

---

## 5. 常见 Filter 获取 URI 方法差异

| 方法 | 行为 |
|------|------|
| `request.getRequestURI()` | 返回编码后的原始 URI |
| `request.getRequestURL()` | 返回完整 URL（含协议+域名） |
| `request.getServletPath()` | 返回 Servlet 路径（可能解码） |
| `request.getPathInfo()` | 返回额外路径信息 |

---

## CTF 检查清单

- [ ] 尝试 `../` 路径遍历绕过白名单匹配
- [ ] 使用 `;` 分号截断 URI 绕过 `endsWith()` 检测
- [ ] URL 编码关键字符绕过字符串匹配
- [ ] 对比 Filter 和实际中间件的 URI 解析差异
