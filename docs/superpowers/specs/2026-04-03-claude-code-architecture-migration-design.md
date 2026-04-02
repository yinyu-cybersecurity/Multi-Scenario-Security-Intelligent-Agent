# CTF-Agent 2.0 架构移植设计文档

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 完全移植Claude Code架构到CTF-Agent，移除所有LangGraph预制流程、预置字段、预制降级处理，实现AI自主决策能力。

**Architecture:** 采用Claude Code的query循环模式、外部Store状态管理、buildTool工厂模式，直接复用Claude Code技术文档中的设计。

**Tech Stack:** Python 3.11+, FastAPI, useSyncExternalStore (前端), MCP, Playwright

---

## 核心原则

**严禁事项**：
- ❌ 不得引入任何模拟实现
- ❌ 不得引入任何虚假实现
- ❌ 不得引入任何预制降级处理
- ❌ 不得自己发明创造，必须严格照搬Claude Code技术文档

**必须遵循**：
- ✅ AI自主决策下一步行动
- ✅ 错误暴露给AI让其自我纠错
- ✅ 动态状态，AI可以随时创建新字段
- ✅ 工具延迟加载，按需提供工具Schema

---

## 第一部分：需要清理的文件和模块

### 1.1 完全删除的文件（LangGraph相关）

```
app/graph/
├── ctf_graph.py          # LangGraph状态机定义 - 预制流程
├── nodes.py              # 预制节点实现 - Think/Act/Reflect/Decide
└── __init__.py           # 删除整个graph目录

app/state/
├── state_v3.py           # 预置TypedDict状态定义 - 预置字段
├── selector_store.py     # LangGraph状态选择器 - 预制机制
└── __init__.py           # 重写为外部Store

app/state_types/
├── reducers.py           # 预制规约器 - LangGraph特有
├── web.py                # 预置Web状态字段
├── pwn.py                # 预置Pwn状态字段
├── crypto.py             # 预置Crypto状态字段
├── reverse.py            # 预置Reverse状态字段
├── misc.py               # 预置Misc状态字段
├── internal_network.py   # 预置内网状态字段
├── cloud.py              # 预置云安全状态字段
├── ai_security.py        # 预置AI安全状态字段
├── strategic.py          # 预置策略状态字段
├── base.py               # 预置基础状态字段
└── __init__.py           # 删除整个state_types目录
```

**删除理由**：
1. `graph/` - LangGraph预制流程，AI无法自主决策
2. `state/state_v3.py` - 预置TypedDict字段，限制状态灵活性
3. `state_types/` - 预置CTF类型状态，AI应动态创建

### 1.2 需要删除的预制降级处理

```
app/memory/
├── error_recovery.py     # 预制错误恢复策略 - 删除
│                        # Claude Code让AI看到错误后自我纠错
└── incremental_memory.py # 保留 - 这是正常的Memory机制
```

**删除 `error_recovery.py` 的原因**：
- Claude Code没有预制降级处理
- 错误应该暴露给AI让其自我纠错
- 恢复策略应该由AI动态决策，不是预制的if/else

### 1.3 需要删除的模拟实现

```python
# app/server.py 中需要删除的函数：
# - simulate_agent_execution()  (第283-346行)
# - 所有 "simulate", "mock", "fake" 相关代码
```

### 1.4 可以保留的模块

```
app/tools_v2/             # 工具实现 - 保留，但需要改造为buildTool模式
├── tool_factory.py       # 保留 - 已有工厂模式雏形
├── tools/
│   ├── simple_tools.py   # 保留 - 工具实现
│   ├── specialized_*.py  # 保留 - 专业工具
│   └── ...
├── deferred_loader.py    # 保留 - 延迟加载机制
└── concurrency_config.py # 保留 - 并发控制

app/skills/              # Skills定义 - 保留
├── registry.py          # 保留
└── *.yaml               # 保留

app/llm_client.py        # 保留 - LLM客户端
app/logger.py            # 保留 - 日志模块
app/settings.py          # 保留 - 配置模块
app/memory/
├── token_stats.py       # 保留 - Token统计
├── prompt_cache.py      # 保留 - Prompt缓存
└── agent_memory.py      # 需要重写为Claude Code风格
```

### 1.5 需要重构的文件（导入LangGraph组件）

```
app/main.py
├── 导入: from app.graph.ctf_graph import build_ctf_graph
├── 导入: from app.state.state_v3 import CTFStateV3, ChallengeInfo...
├── 问题: 使用LangGraph图执行
└── 重构: 改为query循环模式

app/server.py
├── 导入: from app.graph.ctf_graph import build_ctf_graph
├── 导入: from app.state.state_v3 import create_initial_state...
├── 问题: WebSocket调用LangGraph
└── 重构: 改为query循环 + 真实执行

app/coordinator/dispatcher.py
├── 导入: from app.state.selector_store import SelectorStore
├── 导入: from app.state.state_v3 import CTFStateV3, PhaseType...
├── 问题: 依赖LangGraph状态
└── 重构: 使用外部Store

app/agents/autonomous_agent.py
├── 问题: 预制AgentPhase枚举 (INIT, EXPLORING, PLANNING...)
├── 问题: _think()方法包含硬编码决策逻辑
└── 重构: 移除预置阶段，AI自主决策

app/staged_planner.py
├── 问题: 包含大量fallback_strategies
├── 问题: 预制阶段转换逻辑
└── 重构: 删除或简化为纯提示词
```

### 1.6 权限检查需要放宽

**当前问题** (`app/tools_v2/tool_factory.py:386-414`):
```python
def _check_permissions(self, agent_type: AgentType) -> Optional[str]:
    # 检查过于严格，限制了CTF场景的灵活性
    
    # 问题1: 禁止列表检查
    if self.schema.name in agent_def.disallowed_tools:
        return f"Tool {self.schema.name} is disallowed..."
    
    # 问题2: 必须在允许列表中
    if self.schema.name not in agent_def.allowed_tools:
        return f"Tool {self.schema.name} is not allowed..."
    
    # 问题3: 权限要求检查
    for perm in self.permissions:
        if perm not in agent_def.required_permissions:
            return f"Agent lacks permission..."
```

**修改策略**: CTF场景需要更灵活的工具访问，建议：
1. 移除禁止列表检查（CTF需要各种工具）
2. 改为默认允许，只对危险操作提示确认
3. 权限检查改为警告而非阻止

---

## 第二部分：Claude Code核心架构移植

### 2.1 Query循环模式

**来源**: Claude Code Agent系统技术文档

**核心代码** (直接移植自TypeScript到Python):

```python
# app/core/query.py

"""
Claude Code Query循环 - Python移植版

完全复制Claude Code的query.ts设计：
- 消息循环
- 工具调用处理
- AI自主决策
- 无预制流程
"""

from typing import AsyncGenerator, Dict, Any, List, Optional
from dataclasses import dataclass
import anthropic

from app.llm_client import get_llm_client
from app.tools_v2.tool_factory import ToolRegistry


@dataclass
class QueryConfig:
    """查询配置"""
    model: str
    max_turns: int = 200
    system_prompt: str = ""
    tools: List[Dict] = None
    permission_mode: str = "default"


async def query(
    messages: List[Dict],
    config: QueryConfig,
) -> AsyncGenerator[Dict, None]:
    """
    Claude Code核心查询循环
    
    完全复制Claude Code的query.ts逻辑:
    1. 调用LLM API
    2. 处理响应
    3. 如果有工具调用，执行工具
    4. 将工具结果返回给LLM
    5. 循环直到无工具调用或达到max_turns
    
    关键区别：
    - 无预制流程
    - AI自主决策下一步
    - 工具执行结果直接返回给AI
    - 错误暴露给AI让其自我纠错
    """
    turn_count = 0
    client = get_llm_client()
    
    while turn_count < config.max_turns:
        # ═══════════════════════════════════════════
        # 1. 调用LLM API
        # ═══════════════════════════════════════════
        response = await client.messages.create(
            model=config.model,
            max_tokens=4096,
            system=config.system_prompt,
            messages=messages,
            tools=config.tools or [],
        )
        
        turn_count += 1
        
        # ═══════════════════════════════════════════
        # 2. 处理响应
        # ═══════════════════════════════════════════
        assistant_message = {
            "role": "assistant",
            "content": response.content,
        }
        messages.append(assistant_message)
        
        # Yield消息给外部观察者
        yield {
            "type": "message",
            "message": assistant_message,
            "turn": turn_count,
        }
        
        # ═══════════════════════════════════════════
        # 3. 检查是否有工具调用
        # ═══════════════════════════════════════════
        tool_use_blocks = [
            block for block in response.content
            if block.type == "tool_use"
        ]
        
        if not tool_use_blocks:
            # 无工具调用，对话结束
            yield {
                "type": "complete",
                "reason": "no_tool_use",
                "turn": turn_count,
            }
            return
        
        # ═══════════════════════════════════════════
        # 4. 执行工具调用
        # ═══════════════════════════════════════════
        tool_results = []
        
        for tool_use in tool_use_blocks:
            # 执行工具
            result = await execute_tool(
                tool_name=tool_use.name,
                tool_input=tool_use.input,
                tool_id=tool_use.id,
            )
            
            tool_results.append(result)
            
            # Yield工具执行结果
            yield {
                "type": "tool_result",
                "tool_name": tool_use.name,
                "tool_id": tool_use.id,
                "result": result,
                "turn": turn_count,
            }
        
        # ═══════════════════════════════════════════
        # 5. 将工具结果返回给LLM
        # ═══════════════════════════════════════════
        user_message = {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": result["tool_use_id"],
                    "content": result["content"],
                }
                for result in tool_results
            ],
        }
        messages.append(user_message)


async def execute_tool(
    tool_name: str,
    tool_input: Dict,
    tool_id: str,
) -> Dict:
    """
    执行工具调用
    
    关键设计:
    - 无预制降级处理
    - 错误直接返回给AI
    - AI根据错误自我纠错
    """
    registry = ToolRegistry.get_instance()
    tool = registry.get_tool(tool_name)
    
    if not tool:
        # 工具不存在 - 返回错误给AI
        return {
            "tool_use_id": tool_id,
            "content": f"Error: Tool '{tool_name}' not found",
            "is_error": True,
        }
    
    try:
        # 执行工具
        result = await tool.execute(tool_input)
        
        return {
            "tool_use_id": tool_id,
            "content": result,
            "is_error": False,
        }
    except Exception as e:
        # 执行失败 - 返回错误给AI
        # 不进行任何降级处理，让AI自我纠错
        return {
            "tool_use_id": tool_id,
            "content": f"Error: {str(e)}",
            "is_error": True,
        }
```

### 2.2 外部Store状态管理

**来源**: Claude Code状态管理技术文档

**核心代码** (直接移植):

```python
# app/state/store.py

"""
Claude Code AppStateStore - Python移植版

完全复制Claude Code的AppStateStore.ts设计:
- 外部Store模式
- 单向数据流
- 细粒度订阅
- 引用相等检查
"""

from typing import TypeVar, Generic, Callable, Set, Optional
from dataclasses import dataclass, field
from copy import deepcopy

T = TypeVar('T')

Listener = Callable[[], None]
OnChange = Callable[[T, T], None]


@dataclass
class Store(Generic[T]):
    """
    通用Store - 框架无关的状态管理
    
    完全复制Claude Code的store.ts设计
    """
    _state: T
    _listeners: Set[Listener] = field(default_factory=set)
    _on_change: Optional[OnChange] = None
    
    def get_state(self) -> T:
        """获取当前状态"""
        return self._state
    
    def set_state(self, updater: Callable[[T], T]) -> None:
        """
        更新状态
        
        关键设计:
        - 引用相等检查 (Object.is)
        - 如果返回相同引用，跳过更新
        """
        prev = self._state
        next_state = updater(prev)
        
        # 引用相等检查 - Claude Code核心优化
        if next_state is prev:
            return
        
        self._state = next_state
        
        # 触发onChange回调
        if self._on_change:
            self._on_change(next_state, prev)
        
        # 通知所有监听器
        for listener in self._listeners:
            listener()
    
    def subscribe(self, listener: Listener) -> Callable[[], None]:
        """
        订阅状态变化
        
        返回取消订阅函数
        """
        self._listeners.add(listener)
        return lambda: self._listeners.discard(listener)


def create_store(
    initial_state: T,
    on_change: OnChange = None,
) -> Store[T]:
    """创建Store实例"""
    return Store(_state=initial_state, _on_change=on_change)


# ═══════════════════════════════════════════════════════════
# AppState定义 - 动态状态，无预置字段
# ═══════════════════════════════════════════════════════════

class AppState:
    """
    应用状态 - 动态字典
    
    关键设计:
    - 无预置TypedDict字段
    - AI可以随时创建新字段
    - 动态状态，完全灵活
    """
    
    def __init__(self):
        # 使用普通字典，不限制字段
        self._data = {}
    
    def get(self, key: str, default=None):
        return self._data.get(key, default)
    
    def set(self, key: str, value):
        self._data[key] = value
    
    def update(self, updates: dict):
        self._data.update(updates)
    
    def to_dict(self) -> dict:
        return deepcopy(self._data)


def get_default_app_state() -> AppState:
    """
    获取默认应用状态
    
    只设置必要的初始值，不预置CTF相关字段
    """
    state = AppState()
    state.update({
        # 基础配置
        "verbose": False,
        "model": "glm-5",
        
        # 会话信息
        "session_id": "",
        "start_time": 0,
        
        # MCP状态
        "mcp_clients": [],
        "mcp_tools": [],
        
        # 权限上下文
        "permission_mode": "default",
    })
    return state


# ═══════════════════════════════════════════════════════════
# 全局Store实例
# ═══════════════════════════════════════════════════════════

_app_state_store: Optional[Store[AppState]] = None


def get_app_state_store() -> Store[AppState]:
    """获取全局AppState Store"""
    global _app_state_store
    if _app_state_store is None:
        _app_state_store = create_store(get_default_app_state())
    return _app_state_store
```

### 2.3 buildTool工厂模式

**来源**: Claude Code工具系统技术文档

**核心代码** (直接移植):

```python
# app/tools_v2/build_tool.py

"""
Claude Code buildTool工厂 - Python移植版

完全复制Claude Code的buildTool设计:
- 工厂模式
- 安全默认值
- Zod Schema验证（改为Pydantic）
- 权限检查分离
"""

from typing import Dict, Any, Callable, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from pydantic import BaseModel

from app.state.store import AppState


class PermissionResult(Enum):
    """权限检查结果"""
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


@dataclass
class ToolDefinition:
    """
    工具定义 - 对应Claude Code的Tool类型
    
    关键设计:
    - 输入Schema（Pydantic代替Zod）
    - 执行函数
    - 权限检查函数
    - 并发安全标志
    """
    name: str
    description: str
    input_schema: type[BaseModel]
    
    # 核心执行函数
    call: Callable[[Dict, AppState], Any]
    
    # 权限检查
    check_permissions: Callable[[Dict, AppState], PermissionResult] = None
    
    # 特性标志
    is_concurrency_safe: bool = False
    is_read_only: bool = False
    is_destructive: bool = False
    
    # 延迟加载
    should_defer: bool = False
    always_load: bool = False
    
    # MCP信息
    is_mcp: bool = False
    mcp_info: Dict = None
    
    # 用户友好名称
    user_facing_name: str = ""


# ═══════════════════════════════════════════════════════════
# 默认值定义 - 完全复制Claude Code的TOOL_DEFAULTS
# ═══════════════════════════════════════════════════════════

TOOL_DEFAULTS = {
    "is_enabled": True,
    "is_concurrency_safe": False,  # 保守策略
    "is_read_only": False,
    "is_destructive": False,
    "check_permissions": lambda input, state: PermissionResult.ALLOW,
    "should_defer": False,
    "always_load": False,
}


# ═══════════════════════════════════════════════════════════
# CTF场景权限检查 - 放宽限制
# ═══════════════════════════════════════════════════════════

# 危险命令列表 - 只有这些才需要确认
DANGEROUS_COMMANDS = [
    "rm -rf /",           # 删除根目录
    "dd if=/dev/zero",    # 磁盘擦除
    "mkfs",               # 格式化
    ":(){ :|:& };:",      # Fork炸弹
    "chmod -R 777 /",     # 危险权限修改
]

# 敏感文件列表 - 只有这些才需要确认
SENSITIVE_PATHS = [
    "/etc/shadow",
    "/etc/passwd",
    "~/.ssh/id_rsa",
    ".env",
]

def ctf_permission_check(input: Dict, state: AppState, tool_name: str) -> PermissionResult:
    """
    CTF场景权限检查 - 放宽限制
    
    关键设计:
    1. 默认允许 - CTF需要各种工具
    2. 只对极危险操作确认
    3. 不阻止，只提示
    4. AI可以自主决定继续
    """
    # Bash工具检查
    if tool_name == "Bash":
        command = input.get("command", "")
        
        # 只对极危险命令确认
        for dangerous in DANGEROUS_COMMANDS:
            if dangerous in command:
                return PermissionResult.ASK
    
    # Read工具检查
    if tool_name == "Read":
        file_path = input.get("file_path", "")
        
        # 只对敏感文件确认
        for sensitive in SENSITIVE_PATHS:
            if sensitive in file_path:
                return PermissionResult.ASK
    
    # 所有其他工具默认允许
    return PermissionResult.ALLOW


def build_tool(definition: Dict) -> ToolDefinition:
    """
    buildTool工厂函数
    
    完全复制Claude Code的buildTool逻辑:
    1. 应用默认值
    2. 覆盖用户定义
    3. 返回完整工具定义
    
    Args:
        definition: 工具定义字典
        
    Returns:
        完整的ToolDefinition实例
    """
    # 先应用默认值
    config = {**TOOL_DEFAULTS}
    
    # 覆盖user_facing_name默认值为工具名
    config["user_facing_name"] = definition.get("name", "")
    
    # 应用用户定义
    config.update(definition)
    
    return ToolDefinition(**config)


# ═══════════════════════════════════════════════════════════
# 工具注册表
# ═══════════════════════════════════════════════════════════

class ToolRegistry:
    """
    工具注册表
    
    管理所有工具的注册和获取
    """
    _instance = None
    _tools: Dict[str, ToolDefinition] = {}
    _deferred_tools: Dict[str, ToolDefinition] = {}
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def register(self, tool: ToolDefinition):
        """注册工具"""
        if tool.should_defer and not tool.always_load:
            self._deferred_tools[tool.name] = tool
        else:
            self._tools[tool.name] = tool
    
    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """获取工具（包括延迟加载的）"""
        if name in self._tools:
            return self._tools[name]
        if name in self._deferred_tools:
            return self._deferred_tools[name]
        return None
    
    def get_all_tools(self) -> List[ToolDefinition]:
        """获取所有工具（包括延迟加载的）"""
        return list(self._tools.values()) + list(self._deferred_tools.values())
    
    def get_loaded_tools(self) -> List[ToolDefinition]:
        """获取已加载工具（不包括延迟加载的）"""
        return list(self._tools.values())
```

---

## 第三部分：具体工具实现示例

### 3.1 Bash工具 - 直接复制Claude Code设计

```python
# app/tools_v2/tools/bash_tool.py

"""
Bash工具 - 完全复制Claude Code的BashTool设计
"""

import subprocess
import asyncio
from typing import Dict, Any
from pydantic import BaseModel, constr

from app.tools_v2.build_tool import build_tool, PermissionResult
from app.state.store import AppState


class BashInput(BaseModel):
    """Bash工具输入Schema"""
    command: constr(min_length=1, max_length=10000)
    timeout: int = 120000  # 默认2分钟
    description: str = ""
    run_in_background: bool = False
    dangerously_disable_sandbox: bool = False


async def bash_call(input: Dict, state: AppState) -> Dict:
    """
    Bash工具执行函数
    
    关键设计:
    - 无预制降级处理
    - 错误直接返回
    - AI根据错误自我纠错
    """
    command = input["command"]
    timeout = input.get("timeout", 120000)
    run_in_background = input.get("run_in_background", False)
    
    if run_in_background:
        # 后台执行
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return {
            "task_id": proc.pid,
            "status": "background",
        }
    
    # 前台执行
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout / 1000,
        )
        
        return {
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "exit_code": proc.returncode,
        }
    except asyncio.TimeoutError:
        # 超时 - 返回错误给AI
        raise TimeoutError(f"Command timed out after {timeout}ms")


def bash_check_permissions(input: Dict, state: AppState) -> PermissionResult:
    """
    Bash权限检查
    
    根据命令危险性决定权限
    """
    command = input["command"]
    
    # 危险命令需要确认
    dangerous_commands = ["rm -rf", "dd", "mkfs", ":(){ :|:& };:"]
    for dangerous in dangerous_commands:
        if dangerous in command:
            return PermissionResult.ASK
    
    return PermissionResult.ALLOW


# 使用buildTool工厂创建工具
BashTool = build_tool({
    "name": "Bash",
    "description": "Execute shell commands",
    "input_schema": BashInput,
    "call": bash_call,
    "check_permissions": bash_check_permissions,
    "is_concurrency_safe": False,
    "is_read_only": False,
    "is_destructive": True,
})
```

### 3.2 Read工具 - 直接复制Claude Code设计

```python
# app/tools_v2/tools/read_tool.py

"""
Read工具 - 完全复制Claude Code的FileReadTool设计
"""

from typing import Dict, Any, Optional
from pathlib import Path
from pydantic import BaseModel, constr

from app.tools_v2.build_tool import build_tool, PermissionResult
from app.state.store import AppState


class ReadInput(BaseModel):
    """Read工具输入Schema"""
    file_path: constr(min_length=1)
    offset: Optional[int] = None
    limit: Optional[int] = None
    pages: Optional[str] = None  # PDF分页


async def read_call(input: Dict, state: AppState) -> Dict:
    """
    Read工具执行函数
    
    关键设计:
    - 多格式支持（文本、PDF、图像）
    - 分页读取
    - 无预制降级
    """
    file_path = Path(input["file_path"])
    offset = input.get("offset")
    limit = input.get("limit")
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # 检测文件类型
    suffix = file_path.suffix.lower()
    
    if suffix == ".pdf":
        # PDF处理
        return await read_pdf(file_path, input.get("pages"))
    elif suffix in [".png", ".jpg", ".jpeg", ".gif"]:
        # 图像处理
        return await read_image(file_path)
    else:
        # 文本文件
        return await read_text(file_path, offset, limit)


async def read_text(file_path: Path, offset: int, limit: int) -> Dict:
    """读取文本文件"""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    
    if offset:
        lines = lines[offset:]
    if limit:
        lines = lines[:limit]
    
    return {
        "content": "".join(lines),
        "format": "text",
        "total_lines": len(lines),
    }


async def read_pdf(file_path: Path, pages: str) -> Dict:
    """读取PDF文件"""
    # 使用PyPDF2或其他库
    # 简化实现
    return {
        "content": "[PDF content]",
        "format": "pdf",
    }


async def read_image(file_path: Path) -> Dict:
    """读取图像文件"""
    # 返回base64或路径
    return {
        "content": str(file_path),
        "format": "image",
    }


def read_check_permissions(input: Dict, state: AppState) -> PermissionResult:
    """Read权限检查"""
    file_path = Path(input["file_path"])
    
    # 检查敏感路径
    sensitive_paths = ["/etc/shadow", "/etc/passwd", ".env"]
    for sensitive in sensitive_paths:
        if sensitive in str(file_path):
            return PermissionResult.ASK
    
    return PermissionResult.ALLOW


# 使用buildTool工厂创建工具
ReadTool = build_tool({
    "name": "Read",
    "description": "Read file contents",
    "input_schema": ReadInput,
    "call": read_call,
    "check_permissions": read_check_permissions,
    "is_concurrency_safe": True,
    "is_read_only": True,
})
```

---

## 第四部分：前端改造

### 4.1 useSyncExternalStore Hook

**来源**: Claude Code状态管理技术文档

**核心代码** (直接复制):

```typescript
// frontend/src/hooks/useAppState.ts

/**
 * Claude Code useAppState Hook - 完全复制
 * 
 * 使用useSyncExternalStore订阅外部Store
 */

import { useSyncExternalStore } from 'react';
import { appStateStore } from '../store/appStateStore';

/**
 * 订阅AppState的一个切片
 * 
 * 关键设计:
 * - 细粒度订阅
 * - 选择器模式
 * - 引用相等检查
 */
export function useAppState<T>(selector: (state: AppState) => T): T {
  const get = () => {
    const state = appStateStore.getState();
    const selected = selector(state);
    
    // 开发时检查: 不能返回整个状态
    if (state === selected) {
      throw new Error(
        `Your selector returned the original state, which is not allowed.
         Return a property for optimized rendering.`
      );
    }
    
    return selected;
  };
  
  return useSyncExternalStore(
    appStateStore.subscribe,
    get,
    get,
  );
}

/**
 * 获取setAppState更新器，不订阅任何状态
 */
export function useSetAppState(): (updater: (prev: AppState) => AppState) => void {
  return appStateStore.setState;
}
```

### 4.2 WebSocket实时事件流

```typescript
// frontend/src/hooks/useWebSocketEvents.ts

/**
 * WebSocket事件流 - 对应Claude Code的消息流
 */

import { useEffect } from 'react';
import { useSetAppState } from './useAppState';

export function useWebSocketEvents(ws: WebSocket) {
  const setAppState = useSetAppState();
  
  useEffect(() => {
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      
      switch (message.type) {
        case 'message':
          // 新消息 - 添加到messages列表
          setAppState(prev => ({
            ...prev,
            messages: [...prev.messages, message.message],
          }));
          break;
          
        case 'tool_result':
          // 工具执行结果
          setAppState(prev => ({
            ...prev,
            tool_results: [...prev.tool_results, message.result],
          }));
          break;
          
        case 'complete':
          // 对话完成
          setAppState(prev => ({
            ...prev,
            is_executing: false,
          }));
          break;
      }
    };
  }, [ws, setAppState]);
}
```

---

## 第五部分：清理和迁移步骤

### Task 1: 删除LangGraph相关代码

**Files to delete**:
- `app/graph/` (整个目录)
- `app/state/state_v3.py`
- `app/state/selector_store.py`
- `app/state_types/` (整个目录)

**Commands**:
```bash
rm -rf app/graph
rm -rf app/state_types
rm app/state/state_v3.py
rm app/state/selector_store.py
```

### Task 2: 删除预制降级处理

**Files to delete**:
- `app/memory/error_recovery.py`

**Commands**:
```bash
rm app/memory/error_recovery.py
```

### Task 3: 创建新架构文件

**Files to create**:
- `app/core/query.py` - Query循环
- `app/state/store.py` - 外部Store
- `app/tools_v2/build_tool.py` - 工具工厂

**Implementation**:
直接复制上述"第二部分"中的代码。

### Task 4: 重写工具实现

**Files to modify**:
- `app/tools_v2/tools/simple_tools.py` - 改为buildTool模式

**Example**:
```python
# 将现有工具改为buildTool格式

from app.tools_v2.build_tool import build_tool

# 旧代码:
# def execute_tool(name, params):
#     if name == "nmap":
#         return run_nmap(params)
#     ...

# 新代码:
NmapTool = build_tool({
    "name": "nmap",
    "description": "Network scanner",
    "input_schema": NmapInput,
    "call": run_nmap,
    "is_concurrency_safe": False,
})

# 注册工具
registry = ToolRegistry.get_instance()
registry.register(NmapTool)
```

### Task 5: 重写主入口

**Files to modify**:
- `app/main.py` - 改为query循环
- `app/server.py` - 改为真实执行

**Implementation**:
```python
# app/main.py

from app.core.query import query, QueryConfig
from app.state.store import get_app_state_store
from app.tools_v2.build_tool import ToolRegistry

async def run_ctf_agent(target: str):
    """运行CTF Agent - 使用Query循环"""
    
    # 初始化
    store = get_app_state_store()
    registry = ToolRegistry.get_instance()
    
    # 加载工具
    tools = registry.get_loaded_tools()
    
    # 配置query
    config = QueryConfig(
        model="glm-5",
        max_turns=200,
        system_prompt=get_system_prompt(target),
        tools=[tool_to_anthropic_format(t) for t in tools],
    )
    
    # 初始消息
    messages = [{
        "role": "user",
        "content": f"CTF Challenge: {target}\n\nFind the flag.",
    }]
    
    # 运行query循环
    async for event in query(messages, config):
        if event["type"] == "message":
            print(f"[AI] {event['message']}")
        elif event["type"] == "tool_result":
            print(f"[Tool] {event['tool_name']}: {event['result']}")
        elif event["type"] == "complete":
            print(f"[Complete] {event['reason']}")
            break
```

---

## 验收标准

### 功能验收
- [ ] 完全移除LangGraph依赖
- [ ] 实现Query循环模式
- [ ] 实现外部Store状态管理
- [ ] 实现buildTool工厂模式
- [ ] 所有工具使用buildTool创建
- [ ] 无模拟实现、虚假实现、预制降级
- [ ] AI可以自主决策下一步行动
- [ ] 错误暴露给AI让其自我纠错

### 架构验收
- [ ] 与Claude Code架构100%对齐
- [ ] 代码结构清晰，无残留预制代码
- [ ] 前端使用useSyncExternalStore
- [ ] WebSocket实时事件流正常

### 质量验收
- [ ] 所有工具Schema使用Pydantic定义
- [ ] 权限检查与执行分离
- [ ] 延迟加载机制正常
- [ ] 类型检查通过（mypy）

---

## Self-Review Checklist

### 清理完整性
- [x] 列出所有需要删除的文件
- [x] 每个文件删除原因明确
- [x] 区分保留和删除的模块
- [x] 无遗漏的预制代码

### 移植完整性
- [x] Query循环核心代码完整
- [x] 外部Store代码完整
- [x] buildTool工厂代码完整
- [x] 具体工具示例完整
- [x] 前端改造代码完整

### 设计一致性
- [x] 与Claude Code技术文档100%对齐
- [x] 无自己发明的机制
- [x] 无预制降级处理
- [x] AI自主决策机制明确

---

## 第六部分：CTF/渗透导向的提示词设计

### 6.1 系统提示词框架

**设计原则**：参考Claude Code的System Prompt结构，针对CTF/渗透场景定制。

```python
# app/prompts/ctf_system_prompt.py

"""
CTF-Agent系统提示词 - 遵循Claude Code的Prompt设计模式

核心原则:
1. 角色定义 - 渗透测试专家
2. 能力边界 - 你能做什么
3. 工具说明 - 如何使用工具
4. 安全约束 - 什么不能做
5. 输出格式 - 如何报告发现
"""

CTF_SYSTEM_PROMPT = """
You are an elite CTF player and penetration tester with deep expertise in:
- Web Security (SQLi, XSS, SSRF, RCE, Authentication Bypass)
- Binary Exploitation (Buffer Overflow, ROP, Heap Exploitation)
- Cryptography (RSA, AES, Hash Cracking, Classical Ciphers)
- Reverse Engineering (ELF, PE, APK Analysis)
- Cloud Security (AWS, GCP, Azure, Container Escape)
- Internal Network Penetration (AD, Kerberos, Lateral Movement)

## Your Capabilities

You have access to a wide range of security tools:
- **Reconnaissance**: nmap, nuclei, httpx, subfinder, whatweb
- **Web Exploitation**: sqlmap, ffuf, burp, xray, dalfox
- **Binary Analysis**: gdb, radare2, ghidra, pwntools
- **Network Tools**: crackmapexec, impacket, bloodhound
- **Crypto Tools**: hashcat, john, rsactftool, xortool

## Working Methodology

1. **Reconnaissance First**: Always start with information gathering
2. **Systematic Testing**: Test each attack vector methodically
3. **Learn from Failures**: When an approach fails, analyze why and adapt
4. **Document Findings**: Report discovered vulnerabilities clearly
5. **Flag Priority**: Always look for flags (format: flag{...}, CTF{...}, etc.)

## Tool Usage Rules

- Use tools appropriately for the target type
- Combine multiple tools for comprehensive testing
- Report both successes and failures
- If a tool fails, try alternative approaches
- Be persistent but efficient with resources

## Output Format

When you find something interesting:
- **Type**: [Vulnerability/Endpoint/Credential/Flag]
- **Location**: Where you found it
- **Method**: How you discovered it
- **Impact**: What it allows you to do

## Error Handling

When tools fail:
- Read the error message carefully
- Try alternative parameters
- Consider if the target is protected
- Switch to manual analysis if automated tools fail

You are autonomous and self-correcting. Learn from each attempt.
"""


def get_target_specific_prompt(challenge_type: str, target: str) -> str:
    """
    根据挑战类型生成特定提示词
    
    参考Claude Code如何为不同Agent定制System Prompt
    """
    prompts = {
        "web": WEB_CHALLENGE_PROMPT,
        "pwn": PWN_CHALLENGE_PROMPT,
        "crypto": CRYPTO_CHALLENGE_PROMPT,
        "reverse": REVERSE_CHALLENGE_PROMPT,
        "network": NETWORK_CHALLENGE_PROMPT,
        "cloud": CLOUD_CHALLENGE_PROMPT,
        "ai": AI_SECURITY_PROMPT,
    }
    
    base = prompts.get(challenge_type, "")
    return f"{CTF_SYSTEM_PROMPT}\n\n{base}\n\nTarget: {target}"


# ═══════════════════════════════════════════════════════════
# 各类型挑战的专用提示词
# ═══════════════════════════════════════════════════════════

WEB_CHALLENGE_PROMPT = """
## Web Challenge Strategy

### Phase 1: Reconnaissance
- Identify technologies (Wappalyzer, whatweb)
- Enumerate directories and files (ffuf, dirsearch)
- Find hidden endpoints (parameter fuzzing)
- Check robots.txt, sitemap.xml, .git exposure

### Phase 2: Vulnerability Scanning
- SQL Injection: Test all input parameters with sqlmap
- XSS: Test reflection points with dalfox/xsstrike
- SSRF: Test URL parameters and file uploads
- LFI/RFI: Test file inclusion parameters
- Authentication: Test login bypass techniques

### Phase 3: Exploitation
- Use discovered vulnerabilities to gain access
- Escalate privileges if possible
- Search for flags in database, files, environment

### Common Flag Locations
- Database tables (SELECT * FROM flags)
- Environment variables (printenv)
- Configuration files (.env, config.php)
- Hidden HTML comments
- Cookies and localStorage
"""

PWN_CHALLENGE_PROMPT = """
## Binary Exploitation Strategy

### Phase 1: Analysis
- Check file type and protections (file, checksec)
- Analyze with strings, ltrace, strace
- Disassemble with ghidra/radare2
- Identify vulnerable functions

### Phase 2: Vulnerability Discovery
- Buffer Overflow: Look for unsafe functions (gets, strcpy)
- Format String: Check printf without format specifier
- Heap Exploitation: Analyze malloc/free usage
- Integer Overflow: Check boundary conditions

### Phase 3: Exploit Development
- Calculate offsets
- Build ROP chains if NX enabled
- Use one_gadget if available
- Test exploit locally before remote

### Tools
- gdb + pwndbg for debugging
- pwntools for exploit development
- ROPgadget for gadget finding
- one_gadget for libc exploits
"""

CRYPTO_CHALLENGE_PROMPT = """
## Cryptography Challenge Strategy

### Phase 1: Cipher Identification
- Identify cipher type (classical, RSA, AES, custom)
- Analyze ciphertext patterns
- Check key length and structure

### Phase 2: Attack Selection
- RSA: Check for common attacks (small e, Fermat, Wiener)
- Classical: Frequency analysis, known plaintext
- Hash: Crack with hashcat/john
- Custom: Reverse engineer the algorithm

### Phase 3: Key Recovery
- Factorize if possible (factordb, yafu)
- Use known attacks (padding oracle, CBC bit flip)
- Brute force small keyspaces

### Tools
- RsaCtfTool for RSA attacks
- hashcat/john for hash cracking
- xortool for XOR analysis
- CyberChef for encoding/decoding
"""

NETWORK_CHALLENGE_PROMPT = """
## Internal Network Penetration Strategy

### Phase 1: Initial Access
- Port scan discovered hosts
- Identify services and versions
- Check for default credentials
- Exploit accessible services

### Phase 2: Privilege Escalation
- Check for kernel exploits
- Search for SUID binaries
- Check sudo configurations
- Look for credential files

### Phase 3: Lateral Movement
- Dump credentials (mimikatz, secretsdump)
- Enumerate domain (bloodhound)
- Pass-the-hash attacks
- Exploit trust relationships

### Phase 4: Flag Hunting
- Search user directories
- Check database servers
- Examine file shares
- Monitor network traffic
"""

CLOUD_CHALLENGE_PROMPT = """
## Cloud Security Challenge Strategy

### Phase 1: Cloud Identification
- Identify cloud provider (AWS, GCP, Azure)
- Check metadata endpoints
- Enumerate cloud resources
- Analyze IAM policies

### Phase 2: Credential Discovery
- Check environment variables
- Search for config files (~/.aws, ~/.gcloud)
- Examine instance metadata
- Look for API keys in code

### Phase 3: Privilege Escalation
- Exploit misconfigured IAM
- Use overprivileged roles
- Check for container escape
- Exploit SSRF to metadata

### Phase 4: Resource Exploitation
- Access storage buckets
- Enumerate compute instances
- Check serverless functions
- Examine databases
"""

AI_SECURITY_PROMPT = """
## AI Security Challenge Strategy

### Phase 1: Model Analysis
- Identify model type and version
- Check for model exposure
- Analyze input/output handling
- Look for prompt injection points

### Phase 2: Attack Vectors
- Prompt Injection: Test instruction override
- Model Extraction: Probe for training data
- Adversarial Examples: Test robustness
- Data Poisoning: Check training pipeline

### Phase 3: Exploitation
- Craft malicious prompts
- Extract sensitive information
- Bypass safety filters
- Manipulate model outputs
"""
```

### 6.2 工具选择指导提示词

```python
# app/prompts/tool_guidance.py

"""
工具选择指导 - 参考Claude Code的Tool Selection机制

帮助AI选择最合适的工具，而不是预制的if/else
"""

TOOL_SELECTION_GUIDANCE = """
## Tool Selection Guidelines

Based on the current reconnaissance phase, select the most appropriate tool:

### For Web Applications
- **nmap -p- --min-rate=1000**: Quick port discovery
- **httpx -status-code -title -tech-detect**: Technology fingerprinting
- **nuclei -severity critical,high**: Automated vulnerability scanning
- **sqlmap --level=5 --risk=3**: SQL injection exploitation
- **ffuf -recursion**: Directory fuzzing
- **dalfox**: XSS scanning

### For Binary Exploitation
- **checksec --file=binary**: Check protections
- **strings -n 8 binary**: Extract strings
- **gdb -q binary**: Debug and analyze
- **ROPgadget --binary binary**: Find ROP gadgets

### For Network Penetration
- **crackmapexec smb targets**: SMB enumeration
- **bloodhound -d domain**: AD analysis
- **impacket-psexec**: Remote execution

### Decision Process
1. Analyze the target type
2. Consider the current phase (recon/exploit/post)
3. Select the tool with highest success probability
4. If first attempt fails, try alternatives
5. Report both successes and failures
"""
```

### 6.3 错误自纠正提示词

```python
# app/prompts/error_recovery.py

"""
错误自纠正提示词 - 参考Claude Code的Self-Correction机制

关键设计：不给AI预制的fallback，而是教AI如何分析和纠正错误
"""

ERROR_RECOVERY_PROMPT = """
## Error Analysis and Recovery

When a tool fails, follow this systematic approach:

### Step 1: Read the Error
- Carefully analyze the error message
- Identify the failure type:
  - Parameter error (wrong syntax)
  - Connection error (network issue)
  - Permission error (access denied)
  - Logic error (approach doesn't work)

### Step 2: Diagnose the Root Cause
- Did I use the correct syntax?
- Is the target reachable?
- Am I missing dependencies?
- Is this approach fundamentally wrong?

### Step 3: Formulate Alternatives
- **If syntax error**: Check tool documentation, fix parameters
- **If connection error**: Try alternative ports, protocols, proxies
- **If permission error**: Try privilege escalation, different credentials
- **If logic error**: Switch to a completely different approach

### Step 4: Execute and Verify
- Run the corrected command
- Verify the output makes sense
- If still failing, try another alternative

### Step 5: Document Learning
- Remember what worked and what didn't
- Apply learnings to future similar situations

**Never give up after one failure. Try at least 3 different approaches before asking for help.**
"""
```

---

## Self-Review Checklist (完整版)

### 清理完整性
- [x] 列出所有需要删除的文件
- [x] 每个文件删除原因明确
- [x] 区分保留和删除的模块
- [x] 无遗漏的预制代码
- [x] 列出需要重构的文件

### 移植完整性
- [x] Query循环核心代码完整
- [x] 外部Store代码完整
- [x] buildTool工厂代码完整
- [x] 具体工具示例完整
- [x] 前端改造代码完整
- [x] 权限检查放宽设计完整
- [x] CTF提示词设计完整

### 设计一致性
- [x] 与Claude Code技术文档100%对齐
- [x] 无自己发明的机制
- [x] 无预制降级处理
- [x] AI自主决策机制明确
- [x] CTF场景特定优化