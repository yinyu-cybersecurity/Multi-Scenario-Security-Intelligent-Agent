# 环境模拟测试指南

> **参考说明**：本文档展示环境测试**可能的测试场景**
> - 实际测试应根据目标环境特性**选择性地**进行
> - 测试参数（超时时间、并发数等）需根据**实际情况**调整
> - 本文档仅供参考，非固定测试流程

---

## 概述

环境模拟测试用于验证 API 在各种异常和边界条件下的行为，包括网络异常、负载压力、超时处理等。

---

## 测试场景

### 1. 网络异常模拟

#### 超时测试

```http
GET /api/users HTTP/1.1
Host: api.example.com
X-Timeout: 30000

Response Timeout: 30s
```

**预期行为**：
- 服务端应设置合理的超时时间
- 超时后返回 504 Gateway Timeout

#### 连接重置

```http
GET /api/users HTTP/1.1
Host: api.example.com

[Connection Reset by Server]
```

**预期行为**：
- 服务端应优雅处理连接中断
- 不应泄露内部状态

### 2. 负载压力测试

#### 高并发请求

```bash
# 模拟 100 个并发请求
for i in {1..100}; do
  curl -X POST https://api.example.com/api/search \
    -d "query=user$i" &
done
wait
```

**观察指标**：
- 响应时间
- 错误率
- 资源使用率

#### 资源耗尽测试

```bash
# 发送大量请求耗尽连接池
for i in {1..1000}; do
  curl -X GET https://api.example.com/api/users/$i &
done
```

### 3. 边界条件测试

#### 超大 Payload

```http
POST /api/users HTTP/1.1
Content-Type: application/json
Content-Length: 10000000

{"data": "<10MB of data>"}
```

**预期行为**：
- 服务端应限制请求大小
- 返回 413 Payload Too Large

#### 超长字段

```json
{
  "username": "<10000 characters>",
  "email": "a@<10000 characters>.com",
  "bio": "<10000 characters>"
}
```

#### 特殊字符注入

```json
{
  "username": "<script>alert(1)</script>",
  "email": "test@test.com\nCc: evil@evil.com",
  "bio": "{{7*7}}"
}
```

### 4. 协议测试

#### HTTP 方法测试

```http
PATCH /api/users HTTP/1.1
TRACE /api/users HTTP/1.1
CONNECT /api/users HTTP/1.1
```

**预期行为**：
- 仅允许必要的 HTTP 方法
- 返回 405 Method Not Allowed

#### 版本测试

```http
GET /api/users HTTP/1.0
GET /api/users HTTP/0.9
```

### 5. 认证绕过模拟

#### 空 Token

```http
GET /api/user HTTP/1.1
Authorization: Bearer

Response: Should reject with 401
```

#### 过期 Token

```http
GET /api/user HTTP/1.1
Authorization: Bearer <expired_token>

Response: Should reject with 401
```

#### 伪造 Token

```http
GET /api/user HTTP/1.1
Authorization: Bearer fake_token_12345

Response: Should reject with 401
```

### 6. 注入测试

#### SQL 注入模拟

```http
GET /api/users?id=1'; DROP TABLE users;--

Response: Should sanitize input
```

#### NoSQL 注入模拟

```http
GET /api/users?id[$ne]=1

Response: Should validate query syntax
```

#### 命令注入模拟

```http
GET /api/search?q=|cat /etc/passwd

Response: Should sanitize input
```

### 7. 竞态条件测试

#### 并发修改

```bash
# 同时读取和修改同一资源
curl -X GET https://api.example.com/api/account/balance
# Balance: 1000

# 两个并发请求同时扣款
curl -X POST https://api.example.com/api/account/debit -d "amount=600" &
curl -X POST https://api.example.com/api/account/debit -d "amount=600" &

# 预期：只成功一次，余额为 400
# 漏洞：两次都成功，余额为 -200
```

### 8. 会话测试

#### 会话固定

```http
# 攻击者获取会话 ID
GET /api/login HTTP/1.1

Set-Cookie: SESSIONID=attacker_session

# 诱使受害者使用该会话
# 受害者登录
POST /api/login HTTP/1.1
Cookie: SESSIONID=attacker_session

# 攻击者使用同一会话
GET /api/user HTTP/1.1
Cookie: SESSIONID=attacker_session
```

#### 并发会话

```http
# 用户在两个设备登录
POST /api/login HTTP/1.1
Device: Mobile

POST /api/login HTTP/1.1
Device: Desktop

# 检查是否支持并发会话
# 或是否会踢出之前的会话
```

## 自动化测试脚本

```python
import asyncio
import aiohttp

async def stress_test(url, num_requests=100):
    """高并发压力测试"""
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(num_requests):
            task = session.get(f"{url}/api/users/{i}")
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        return responses

async def injection_test(url):
    """注入测试"""
    payloads = [
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "{{7*7}}",
        "$(whoami)",
        "| cat /etc/passwd"
    ]
    
    results = []
    async with aiohttp.ClientSession() as session:
        for payload in payloads:
            async with session.get(f"{url}/api/search", params={"q": payload}) as resp:
                results.append({
                    "payload": payload,
                    "status": resp.status,
                    "body": await resp.text()
                })
    return results
```

## 预期结果记录

| 测试场景 | 预期状态码 | 实际状态码 | 通过 |
|---------|-----------|-----------|-----|
| 超时测试 | 504 | ? | ? |
| 超大 Payload | 413 | ? | ? |
| SQL 注入 | 400/500 | ? | ? |
| 空 Token | 401 | ? | ? |
| 非法方法 | 405 | ? | ? |
