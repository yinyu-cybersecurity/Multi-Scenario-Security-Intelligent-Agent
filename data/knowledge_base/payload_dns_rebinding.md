# DNS Rebinding - DNS重绑定

[SEARCH_KEYWORDS]
漏洞类型: DNS Rebinding DNS重绑定 DNS Rebinding Attack
攻击类型: Same-Origin Policy Bypass SSRF Internal Network Access
关键词: DNS rebinding same-origin policy TTL IP address resolution internal
技术: TTL Manipulation CNAME Bypass 0.0.0.0 localhost Internal IP
工具: singularity rbndr rebinder

[CONTENT]

## DNS重绑定概述

DNS重绑定将攻击者控制的机器名称的IP地址更改为目标应用程序的IP地址，绕过同源策略，允许浏览器向目标应用程序发出任意请求并读取响应。

## 攻击流程

### 设置阶段

1. 注册恶意域名（如 `malicious.com`）
2. 配置能够将 `malicious.com` 解析为不同IP地址的自定义DNS服务器

### 初始受害者交互

1. 在 `malicious.com` 上创建包含恶意JavaScript的网页
2. 诱使受害者访问恶意网页（钓鱼、社会工程）

### 初始DNS解析

1. 受害者浏览器访问 `malicious.com`
2. DNS服务器解析为初始合法IP地址（如 203.0.113.1）

### 重绑定到内部IP

1. DNS服务器将 `malicious.com` 更新解析为私有/内部IP地址（如 192.168.1.1）
2. 通过设置非常短的TTL强制浏览器重新解析域名

### 同源利用

浏览器将后续响应视为来自同源（`malicious.com`），恶意JavaScript可以向内部IP地址发出请求。

## 攻击示例

1. 注册域名
2. 设置Singularity of Origin
3. 编辑autoattack HTML页面
4. 浏览 `http://rebinder.your.domain:8080/autoattack.html`
5. 等待攻击完成

## 防护绕过

### 0.0.0.0绕过

使用IP地址 0.0.0.0 访问localhost，绕过阻止127.0.0.1的过滤器。

### CNAME绕过

使用DNS CNAME记录绕过阻止内部IP地址的DNS保护：

```bash
$ dig cname.example.com +noall +answer
cname.example.com.    381    IN    CNAME    target.local.
```

### localhost绕过

使用"localhost"作为CNAME记录绕过阻止127.0.0.1的过滤器：

```bash
$ dig www.example.com +noall +answer
localhost.example.com.    381    IN    CNAME    localhost.
```

## 工具

- singularity - DNS重绑定攻击框架
- rebind.it - Singularity Web客户端
- rbndr - 简单DNS重绑定服务
- rebinder - rbndr工具助手

## 参考文档

原始来源: PayloadsAllTheThings/DNS Rebinding/README.md