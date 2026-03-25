# CTF-Agent API 文档

## 概述

CTF-Agent Web API 提供任务管理、状态查询、实时监控等功能。

**基础URL**: `http://localhost:5000`

---

## 任务管理 API

### 1. 启动任务

**POST** `/api/task/start`

启动一个新的渗透测试任务。

**请求体**:
```json
{
    "target_url": "http://target.com",
    "task_name": "Optional task name",
    "task_description": "Optional description"
}
```

**响应**:
```json
{
    "task_id": "task_1710000000000",
    "status": "started"
}
```

---

### 2. 获取任务状态

**GET** `/api/task/<task_id>`

获取指定任务的详细状态。

**响应**:
```json
{
    "id": "task_1710000000000",
    "target_url": "http://target.com",
    "status": "running",
    "current_node": "attacker",
    "visited_nodes": ["recon", "analyst"],
    "progress": 45,
    "created_at": "2024-03-10 10:00:00",
    "task_name": "Target CTF",
    "found_flag": false,
    "final_flag": "",
    "vuln_candidates": [...],
    "credentials": [...],
    "internal_hosts": [...],
    "current_mode": "exploit",
    "execution_steps": 12
}
```

**任务状态值**:
- `running`: 运行中
- `completed`: 已完成
- `error`: 出错
- `cancelled`: 已取消

---

### 3. 获取任务日志

**GET** `/api/task/<task_id>/logs?offset=0`

获取任务执行日志。

**参数**:
- `offset`: 日志偏移量，用于增量获取

**响应**:
```json
{
    "logs": [
        {
            "time": "10:00:01",
            "msg": "[recon] Starting HTTP reconnaissance...",
            "type": "info"
        }
    ],
    "total": 100
}
```

**日志类型**:
- `info`: 信息
- `success`: 成功
- `warning`: 警告
- `error`: 错误

---

### 4. 取消任务

**POST** `/api/task/<task_id>/cancel`

取消正在运行的任务。

**响应**:
```json
{
    "status": "cancelled"
}
```

---

### 5. 获取任务列表

**GET** `/api/tasks`

获取所有任务列表。

**响应**:
```json
{
    "tasks": [
        {
            "id": "task_1710000000000",
            "target_url": "http://target.com",
            "status": "completed",
            "progress": 100,
            "created_at": "2024-03-10 10:00:00",
            "task_name": "Target CTF",
            "found_flag": true
        }
    ]
}
```

---

### 6. 日志流 (SSE)

**GET** `/api/task/<task_id>/stream`

通过 Server-Sent Events 实时推送日志。

**响应格式**:
```
data: {"time":"10:00:01","msg":"[recon] Starting...","type":"info"}

data: {"time":"10:00:02","msg":"[analyst] Analyzing...","type":"info"}

data: {"type":"end"}
```

---

## 系统状态 API

### 7. 系统状态

**GET** `/api/system/status`

获取系统整体状态。

**响应**:
```json
{
    "llm_connected": true,
    "tools_loaded": 44,
    "active_sessions": 2,
    "start_time": "2024-03-10T09:00:00",
    "tasks_total": 10,
    "tasks_running": 2,
    "tasks_completed": 8
}
```

---

### 8. 图结构

**GET** `/api/graph`

获取 LangGraph 节点和边结构，用于前端可视化。

**响应**:
```json
{
    "nodes": [
        {
            "id": "recon",
            "name": "侦察兵",
            "group": "web",
            "description": "HTTP请求、指纹识别"
        }
    ],
    "edges": [
        {"source": "recon", "target": "analyst"}
    ],
    "groups": {
        "web": {"name": "Web攻击", "color": "#67C23A"},
        "internal": {"name": "内网渗透", "color": "#F56C6C"}
    }
}
```

---

### 9. 工具列表

**GET** `/api/tools`

获取已注册的工具列表。

**响应**:
```json
{
    "tools": [
        {
            "name": "sqlmap",
            "description": "SQL注入自动化工具",
            "available": true
        }
    ]
}
```

---

### 10. 活跃会话

**GET** `/api/sessions`

获取当前的 Shell/SSH 会话。

**响应**:
```json
{
    "sessions": [
        {
            "id": "session_001",
            "type": "webshell",
            "target": "192.168.1.100",
            "os_type": "linux"
        }
    ]
}
```

---

## 监控 API

### 11. LLM 状态

**GET** `/api/llm/status`

获取 LLM 调用状态和速率限制。

**响应**:
```json
{
    "requests_today": 150,
    "rate_limit_percent": 45,
    "avg_response_time": 1200
}
```

---

### 12. 压缩状态

**GET** `/api/compression/status`

获取上下文压缩统计。

**响应**:
```json
{
    "total_compressions": 10,
    "tokens_saved": 50000,
    "compression_ratio": 0.35
}
```

---

### 13. 错误恢复状态

**GET** `/api/system/recovery`

获取自我纠错系统状态。

**响应**:
```json
{
    "recovery_stats": {
        "total_errors": 5,
        "recovered": 4,
        "recovering": false
    },
    "recent_errors": [...]
}
```

---

### 14. 策略评估统计

**GET** `/api/strategy/statistics`

获取攻击策略评估统计。

**响应**:
```json
{
    "total_evaluations": 50,
    "avg_success_rate": 0.65,
    "top_strategies": [...]
}
```

---

### 15. 评估攻击策略

**POST** `/api/strategy/evaluate`

评估特定攻击策略的成功概率。

**请求体**:
```json
{
    "tool": "sqlmap",
    "target": "http://target.com/page?id=1",
    "vuln_type": "SQL Injection",
    "context": {}
}
```

**响应**:
```json
{
    "score": 0.85,
    "confidence": 0.9,
    "reasoning": "参数存在明显SQL注入点...",
    "recommendations": ["使用--batch参数", "尝试--dbs"],
    "alternatives": [...]
}
```

---

## 持久化 API

### 16. 持久化任务列表

**GET** `/api/persistence/tasks?status=running`

获取持久化存储的任务记录。

**参数**:
- `status`: 按状态过滤 (可选)

---

### 17. 任务统计

**GET** `/api/persistence/statistics`

获取任务执行统计信息。

**响应**:
```json
{
    "total_tasks": 100,
    "success_rate": 0.75,
    "avg_duration": 1800,
    "common_vulns": [...]
}
```

---

## 健康检查

### 18. 健康检查

**GET** `/api/health`

检查服务是否正常运行。

**响应**:
```json
{
    "status": "ok",
    "timestamp": "2024-03-10T10:00:00"
}
```

---

## 错误响应

所有 API 在出错时返回统一格式:

```json
{
    "error": "Error message description"
}
```

常见 HTTP 状态码:
- `400`: 请求参数错误
- `404`: 资源不存在
- `500`: 服务器内部错误
- `503`: 服务不可用（模块未加载）

---

## WebSocket 事件

通过 `/api/task/<task_id>/stream` 可以接收实时事件:

| 事件类型 | 说明 |
|---------|------|
| `info` | 信息日志 |
| `success` | 成功日志 |
| `warning` | 警告日志 |
| `error` | 错误日志 |
| `end` | 任务结束 |

---

## 使用示例

### Python 示例

```python
import requests

# 启动任务
response = requests.post('http://localhost:5000/api/task/start', json={
    'target_url': 'http://target.com'
})
task_id = response.json()['task_id']

# 轮询状态
while True:
    status = requests.get(f'http://localhost:5000/api/task/{task_id}').json()
    if status['status'] != 'running':
        break
    print(f"Progress: {status['progress']}%")

# 获取结果
if status['found_flag']:
    print(f"FLAG: {status['final_flag']}")
```

### cURL 示例

```bash
# 启动任务
curl -X POST http://localhost:5000/api/task/start \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://target.com"}'

# 获取状态
curl http://localhost:5000/api/task/task_1710000000000
```