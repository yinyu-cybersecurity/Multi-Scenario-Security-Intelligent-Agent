# 缓存与CDN安全

## 1. 缓存投毒

### HTTP头投毒

```
X-Forwarded-Host: attacker.com
```

### 缓存污染

```
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
```

## 2. 缓存欺骗

### Web缓存欺骗

```
http://target.com/css/..;/main.js
```

## 3. CDN绕过

### 源站IP发现

```
nslookup target.com
dig target.com
```

### 配置错误

### 回源请求利用
