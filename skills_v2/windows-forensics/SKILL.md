---
name: windows-forensics
description: Use when encountering Windows 应急响应 - 文件排查、进程排查、注册表检查、日志分析、隐藏用户、Webshell 查找
---

# Windows 应急响应

## Info

- **Tags**: windows, forensics, incident-response, webshell
- **场景**: Webshell、隐藏账户、RDP 入侵、挖矿木马

---

## 1. 文件排查

```cmd
# 临时目录
dir "%TEMP%" /a /o-d /t:w | findstr /i "\.exe \.dll \.bat \.ps1 \.scr \.msi"

# 最近文件
%UserProfile%\Recent

# Webshell 查找
findstr /m /i /s /r /c:"\<eval\>" /c:"\<assert\>" /c:"\<system\>" /c:"\<exec\>" /c:"\<passthru\>" /c:"\<shell_exec\>" /c:"\<preg_replace\>.*\/e" /c:"\<base64_decode\>" /c:"\<str_rot13\>" *.php *.php3 *.php4 *.phtml

# 按时间查找文件（资源管理器排序）
# 修改时间早于创建时间 → 可疑（菜刀类工具只改 Modify Time）
```

---

## 2. 进程排查

```cmd
# 网络连接
netstat -ano
# LISTENING=监听 | ESTABLISHED=已连接 | CLOSE_WAIT=对方关闭

# 定位进程
tasklist | findstr <PID>
wmic process where "Name='chrome.exe'" get ProcessId,ExecutablePath
```

---

## 3. 系统信息排查

### 环境变量检查

```cmd
echo %TEMP%
echo %PATHEXT%
# 正常值: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC

# PATH 注入检查
reg query "HKCU\Environment" /v PATH
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH
```

### 隐藏用户检查

```cmd
# 图形界面
lusrmgr.msc

# 命令行
net user
net localgroup administrators

# PowerShell（可显示 $ 结尾隐藏账户）
Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon

# 注册表（查看所有用户）
reg query "HKLM\SAM\SAM\Domains\Account\Users\Names"
```

### 计划任务

```
taskmgr → 启动
msconfig → 启动项
schtasks /query /fo LIST /v
```

### 注册表自启动

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

### 开启远程桌面

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

### 当前会话

```cmd
query user    # 查看会话
logoff <ID>   # 踢出用户
```

---

## 4. 日志分析

### 事件查看器

```
compmgmt.msc → 事件查看器 → Windows 日志 → 安全
```

### 关键事件 ID

| ID | 说明 |
|----|------|
| 4624 | 成功登录 |
| 4625 | 登录失败（暴力破解） |
| 4648 | 显式凭据登录（runas） |
| 4720 | 用户账户创建 |
| 4776 | 域控验证尝试 |

### PowerShell 日志查询

```powershell
# 最近 24 小时成功登录
Get-WinEvent -FilterHashtable @{
    LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-24)
}

# 登录失败
Get-WinEvent -FilterHashtable @{
    LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-24)
}

# 用户创建（最近 7 天）
Get-WinEvent -FilterHashtable @{
    LogName='Security'; ID=4720; StartTime=(Get-Date).AddDays(-7)
}
```

---

## 5. Webshell 排查工具

- **D盾** - Windows 图形界面
- **河马 Webshell** - 命令行扫描
- **findstr** - 内置命令快速搜索

---

## CTF 检查清单

- [ ] `netstat -ano` 查可疑连接
- [ ] `%TEMP%` 查临时文件
- [ ] `findstr` 搜索 Webshell 特征
- [ ] `net user` + 注册表查隐藏用户
- [ ] `schtasks` + 注册表 Run 查自启动
- [ ] 事件查看器 4624/4625 查登录
- [ ] `query user` 查 RDP 会话
- [ ] PATH / PATHEXT 查环境变量注入
