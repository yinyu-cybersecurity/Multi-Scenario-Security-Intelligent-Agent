---
name: auto-recon
description: Use when encountering 自动化信息收集 - 一键资产发现与漏洞探测，整合多种工具进行快速全面的信息收集
---

# 自动化信息收集

## Info

- **Tags**: recon, automation, asset-discovery, information-gathering, enumeration

---

## 1. 端口扫描

```bash
# 快速端口扫描
nmap -sS -T4 --top-ports 1000 -Pn target.com

# 全端口扫描
nmap -sS -p- -T4 -Pn target.com

# 服务版本检测
nmap -sV -sC -O -p 22,80,443,3306,8080 target.com

# 使用 masscan 快速发现开放端口
masscan -p1-65535 target.com --rate=1000 -e tun0
```

---

## 2. Web 枚举

```bash
# 目录爆破
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/big.txt -t 50
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,txt,html,js

# 子域名枚举
subfinder -d target.com -o subs.txt
amass enum -d target.com -o amass_subs.txt
assetfinder --subs-only target.com

# 技术栈识别
whatweb http://target.com
wafw00f http://target.com
```

---

## 3. 漏洞扫描

```bash
# 使用 nuclei 扫描已知漏洞
nuclei -u http://target.com -t ~/nuclei-templates/ -severity critical,high

# 快速漏洞检测
nuclei -u http://target.com -tags cve,exposure,config

# SQLMap 自动注入
sqlmap -u "http://target.com/page?id=1" --batch --risk=3 --level=3

# XSS 检测
dalfox url "http://target.com/search?q=test"
```

---

## 4. 综合自动化脚本

```bash
#!/bin/bash
# 一键信息收集脚本
TARGET=$1
echo "[*] 开始对 $TARGET 进行信息收集"

# 1. 端口扫描
nmap -sS -T4 --top-ports 5000 -Pn -oN nmap-top5000.txt $TARGET

# 2. 子域名
subfinder -d $TARGET -silent | httpx -silent -o alive_subs.txt

# 3. Web 目录
cat alive_subs.txt | while read url; do
  gobuster dir -u $url -w /usr/share/wordlists/dirb/common.txt -t 30 -q -o "gobuster_$(echo $url | tr '/' '_').txt"
done

# 4. 漏洞扫描
cat alive_subs.txt | nuclei -t ~/nuclei-templates/ -severity critical,high -o nuclei_results.txt

echo "[*] 信息收集完成"
```

---

## 5. 内网信息收集

```bash
# 存活主机探测
nmap -sn 10.10.10.0/24

# SMB 枚举
enum4linux -a 10.10.10.1
smbclient -L //10.10.10.1

# LDAP 枚举
ldapsearch -x -h 10.10.10.1 -b "DC=domain,DC=local" "*"

# Kerberos 枚举
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='DOMAIN' target
```

---

## 6. 关键文件查找

```bash
# 敏感文件泄露检测
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common-and-french.txt -x bak,old,backup,sql,log,env,yaml,json,conf,ini

# 常见敏感路径
/.env
/config.php.bak
/backup.sql
/wp-config.php
/.git/config
/.svn/entries
/server-status
/phpinfo.php
```
