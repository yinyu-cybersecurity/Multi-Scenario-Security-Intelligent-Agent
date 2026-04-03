# CTF-Agent 项目配置

## 项目概述

CTF-Agent 是一个基于 Claude Code 架构的智能 CTF 自动化求解框架，支持 Web、Pwn、Crypto、Reverse、Misc、内网渗透、云安全、AI安全等 8 个 CTF 方向。

**当前版本**: 2.0
**架构基座**: Claude Code Query Loop + External Store

---

## 核心架构

### Claude Code Query 循环

CTF-Agent 采用 Claude Code 的 Query 循环模式，实现 AI 完全自主决策：

```python
from app.core.query import query, QueryConfig

async def run_agent(target: str):
    config = QueryConfig(
        model="glm-5",
        max_turns=200,
        system_prompt="You are a CTF player...",
    )

    messages = [{"role": "user", "content": f"Target: {target}"}]

    async for event in query(messages, config):
        if event["type"] == "message":
            print(event["message"]["content"])
        elif event["type"] == "complete":
            break
```

### 外部 Store 状态管理

使用 Claude Code 的 External Store 模式，实现细粒度订阅和引用相等检查：

```python
from app.state.store import get_app_state_store

store = get_app_state_store()

# 获取状态
state = store.get_state()

# 更新状态（触发引用相等检查）
store.set_state(lambda prev: prev.update({"key": "value"}))

# 订阅变化
unsubscribe = store.subscribe(lambda: print("State changed!"))
```

### 时间管理

超时是唯一熔断条件，AI 自主决定时间分配：

```python
from app.core.time_manager import TimeManager, TaskType

tm = TimeManager()
budget = tm.create_budget("session-1", TaskType.CTF_SINGLE_FLAG)

# 检查超时
if budget.is_timeout:
    print("Time's up!")

# 获取时间提示给 AI
prompt = budget.get_status_prompt()
```

---

## 工具框架

### 原生工具执行器

直接调用系统工具，无需 Docker 开销：

```python
from app.tools_v2.native_executor import get_native_executor

executor = get_native_executor()

# 检查工具可用性
availability = await executor.check_available("sqlmap")

# 执行工具
result = await executor.execute(
    tool_name="sqlmap",
    args=["-u", "http://target.com?id=1", "--dbs"],
    timeout=120000
)
```

### buildTool 工厂模式

```python
from app.tools_v2.tool_factory import buildTool

# 创建工具
sqlmap_tool = buildTool(
    name="sqlmap",
    description="SQL注入自动化利用工具",
    parameters={
        "type": "object",
        "properties": {
            "target_url": {"type": "string", "format": "uri"},
            "level": {"type": "integer", "minimum": 1, "maximum": 5}
        },
        "required": ["target_url"]
    }
)
```

---

## MCP 插件配置

### 已启用插件

| 插件 | 功能 | CTF场景 |
|------|------|---------|
| semgrep-plugin | 静态代码扫描 | 漏洞模式匹配 |
| context7 | 文档查询 | POC查询、技术文档 |
| playwright | 浏览器自动化 | XSS/CSRF测试 |
| chrome-devtools-mcp | 浏览器调试 | 前端漏洞利用 |

---

## 代码规范

### 安全约束

1. **禁止硬编码敏感信息**: API Key、密码等必须从环境变量读取
2. **命令注入防护**: 所有用户输入必须经过验证
3. **超时控制**: 所有工具调用设置合理超时

### 错误处理

```python
def tool_handler(params: Dict, context: Dict) -> Dict:
    try:
        result = do_something(params)
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}
```

---

## 目录结构

```
app/
├── core/              # 核心模块
│   ├── query.py       # Query循环
│   └── time_manager.py # 时间管理
├── state/             # 状态管理
│   └── store.py       # 外部Store
├── tools_v2/          # 工具系统
│   ├── native_executor.py  # 原生执行器
│   └── tool_factory.py     # 工具工厂
├── prompts/           # 提示词
│   ├── ctf_system_prompt.py
│   ├── tool_guidance.py
│   └── error_recovery.py
└── skills/            # Skill系统
    └── skill_loader.py # 延迟加载

frontend/src/
├── components/
│   └── DecisionFlow/  # 决策流组件
├── hooks/
│   └── useDecisionFlow.ts
└── store/

settings.json          # 单一配置文件
scripts/install_tools.sh # 工具安装脚本
```

---

## 配置文件

### settings.json

```json
{
  "model": {
    "name": "glm-5",
    "base_url": "https://open.bigmodel.cn/api/paas/v4/",
    "api_key": "${LLM_API_KEY}"
  },
  "timeouts": {
    "ctf_single": 1800,
    "ctf_multi": 3600
  },
  "tools": {
    "native_execution": true
  }
}
```

---

## 开发指南

### 运行 CTF Agent

```bash
# 命令行
python -m app.main "http://target.com"

# 带参数
python -m app.main "http://target.com" -t web --timeout 30
```

### 安装工具

```bash
# Linux/macOS
bash scripts/install_tools.sh

# Windows
# 手动安装 nmap, Python, Go 工具
```

---

## 相关文档

- [架构迁移设计文档](docs/superpowers/specs/2026-04-03-claude-code-architecture-migration-design.md)
- [架构迁移实施计划](docs/superpowers/plans/2026-04-03-claude-code-architecture-migration-plan.md)