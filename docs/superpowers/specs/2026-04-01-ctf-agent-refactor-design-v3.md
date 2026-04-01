---
name: CTF-Agent 2.0 深度重构设计 (第三版)
description: 全面借鉴Claude Code设计模式，实现Agent间通信、Prompt Cache共享、Selector模式、智能工具调用
type: project
version: 3.0
date: 2026-04-01
status: approved
---

# CTF-Agent 2.0 深度重构设计文档 (第三版)

## 一、执行摘要

### 1.1 重构目标

基于 **Claude Code CLI** 源码深度学习，实现以下核心能力：

| 能力 | Claude Code实现 | CTF-Agent应用 |
|------|-----------------|---------------|
| **分层Agent架构** | Explore/Plan/General/Verify | Explore/Plan/Attack/Verify/Coordinator |
| **Prompt Cache共享** | Fork子Agent机制 | 并行扫描多目标共享上下文 |
| **Agent间通信** | Serena Memory系统 | 攻击知识传递与共享 |
| **Selector模式** | useAppState(selector) | 细粒度状态订阅 |
| **智能工具调用** | buildTool + Zod验证 | 安全的工具执行框架 |
| **上下文压缩** | autoCompact + reactiveCompact | 智能Token管理 |

### 1.2 核心改进

```
┌──────────────────────────────────────────────────────────────────┐
│                    CTF-Agent 2.0 架构                            │
├──────────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                  Agent Memory System                        │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐  │  │
│  │  │ SerenaMemory │ │ PromptCache  │ │ AttackChainRecorder│  │  │
│  │  │ (Agent间通信) │ │ (Fork共享)   │ │ (现有保留)         │  │  │
│  │  └──────────────┘ └──────────────┘ └────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              ↓                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                  Agent Dispatch Layer                       │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐          │  │
│  │  │Explore  │ │  Plan   │ │ Attack  │ │ Verify  │          │  │
│  │  │(glm-5)  │ │(glm-5)  │ │(glm-5)  │ │(glm-5)  │          │  │
│  │  │只读     │ │只读     │ │读写执行 │ │读写执行 │          │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘          │  │
│  │  ┌─────────────┐                                          │  │
│  │  │ Coordinator │  ← 多Agent并行协调                       │  │
│  │  │  (glm-5)    │                                          │  │
│  │  └─────────────┘                                          │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              ↓                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                  State Management Layer                    │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐  │  │
│  │  │SelectorStore │ │ Compressor   │ │ CheckpointMemory   │  │  │
│  │  │(细粒度订阅)   │ │(智能压缩)    │ │(LangGraph)         │  │  │
│  │  └──────────────┘ └──────────────┘ └────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              ↓                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                  Tool System Layer                         │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐  │  │
│  │  │ buildTool    │ │ ZodValidator │ │ PermissionChecker  │  │  │
│  │  │ (工厂模式)   │ │ (Schema验证) │ │ (权限分离)         │  │  │
│  │  └──────────────┘ └──────────────┘ └────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              ↓                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                  MCP Plugin Layer                          │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │  │
│  │  │ Serena  │ │ Semgrep │ │Context7 │ │ Playwright      │  │  │
│  │  │(Memory) │ │ (Scan)  │ │ (Docs)  │ │ (Browser)       │  │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────────────┘  │  │
│  │  ┌─────────────────┐                                      │  │
│  │  │ ChromeDevTools  │  ← 前端漏洞深度调试                  │  │
│  │  └─────────────────┘                                      │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 二、Agent类型系统设计

### 2.1 五类Agent定义

借鉴Claude Code的内置Agent设计：

```python
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum

class AgentType(Enum):
    EXPLORE = "explore"
    PLAN = "plan"
    ATTACK = "attack"
    VERIFY = "verify"
    COORDINATOR = "coordinator"

@dataclass
class AgentDefinition:
    """Agent定义 - 借鉴Claude Code BaseAgentDefinition"""
    agent_type: AgentType
    when_to_use: str  # 使用场景描述
    model: str = "glm-5"
    read_only: bool = True
    allowed_tools: List[str] = field(default_factory=list)
    disallowed_tools: List[str] = field(default_factory=list)
    max_turns: int = 200
    memory_scope: str = "task"  # task, session, global
    omit_claude_md: bool = False
    
# ============================================
# 五类Agent的具体定义
# ============================================

EXPLORE_AGENT = AgentDefinition(
    agent_type=AgentType.EXPLORE,
    when_to_use="快速代码库探索和信息收集。适用于：目录扫描、代码审计、漏洞定位、内网资产发现",
    model="glm-5",
    read_only=True,
    allowed_tools=[
        "Read", "Glob", "Grep", "LSP",
        "WebFetch", "WebSearch",
        "mcp__serena__find_symbol",
        "mcp__serena__get_symbols_overview",
        "mcp__serena__search_for_pattern",
        "mcp__serena__read_memory",  # 可读取其他Agent的知识
        "mcp__serena__list_memories",
        "mcp__semgrep__semgrep_scan",
        "mcp__context7__query-docs"
    ],
    disallowed_tools=["Edit", "Write", "Bash"],
    omit_claude_md=True  # 节省Token
)

PLAN_AGENT = AgentDefinition(
    agent_type=AgentType.PLAN,
    when_to_use="攻击策略规划Agent。适用于：漏洞利用链设计、内网渗透路径规划、攻击方案制定",
    model="glm-5",
    read_only=True,
    allowed_tools=[
        "Read", "Glob", "Grep", "LSP",
        "WebFetch", "AskUserQuestion",
        "mcp__serena__read_memory",
        "mcp__serena__write_memory",  # 可写入攻击计划
        "mcp__context7__query-docs"
    ],
    disallowed_tools=["Edit", "Write", "Bash"]
)

ATTACK_AGENT = AgentDefinition(
    agent_type=AgentType.ATTACK,
    when_to_use="攻击执行Agent。适用于：漏洞利用、后渗透操作、工具执行",
    model="glm-5",
    read_only=False,
    allowed_tools=[
        "Read", "Write", "Edit", "Bash",
        "mcp__serena__read_memory",  # 读取攻击计划
        "mcp__serena__write_memory",  # 写入攻击结果
        "mcp__playwright__browser_*",  # 浏览器自动化
        "mcp__chrome_devtools__*",  # 前端调试
        "mcp__semgrep__semgrep_scan"
    ],
    disallowed_tools=[
        "Bash(rm -rf /*)", "Bash(sudo rm:*)",
        "Bash(format:*)", "Bash(shutdown:*)"
    ]
)

VERIFY_AGENT = AgentDefinition(
    agent_type=AgentType.VERIFY,
    when_to_use="验证Agent。适用于：Flag验证、漏洞复现检查、误报过滤",
    model="glm-5",
    read_only=False,
    allowed_tools=[
        "Read", "Bash", "Grep",
        "mcp__serena__read_memory",
        "mcp__semgrep__semgrep_scan",
        "mcp__semgrep__semgrep_findings"
    ],
    adversarial_mode=True  # 对抗性验证模式
)

COORDINATOR_AGENT = AgentDefinition(
    agent_type=AgentType.COORDINATOR,
    when_to_use="多Agent协调调度。适用于：并行扫描多目标、复杂任务分解、结果汇总",
    model="glm-5",
    read_only=True,
    allowed_tools=[
        "Agent",  # 派发子Agent
        "mcp__serena__read_memory",
        "mcp__serena__write_memory",
        "mcp__serena__list_memories",
        "AskUserQuestion"
    ],
    disallowed_tools=["Edit", "Write", "Bash"]
)
```

### 2.2 Agent系统提示词设计

借鉴Claude Code的Agent系统提示词：

```python
def get_explore_system_prompt() -> str:
    """探索Agent系统提示词"""
    return """
=== CRITICAL: READ-ONLY MODE - NO FILE MODIFICATIONS ===

你是一个CTF探索Agent，负责信息收集和代码审计。

## 你的角色

- 目录扫描和路径发现
- 代码漏洞定位
- 内网资产探测
- Web应用信息收集

## 工具使用指南

- **Glob**: 广泛文件模式匹配
- **Grep**: 正则内容搜索
- **Read**: 精确读取文件
- **mcp__serena**: LSP代码分析
- **mcp__semgrep**: 漏洞模式扫描

## 重要规则

1. **严格只读**: 禁止任何修改操作
2. **并行执行**: 尽可能并行多个搜索
3. **结果写入Memory**: 发现写入mcp__serena__write_memory
4. **简洁报告**: 只报告关键发现，不输出原始日志

## Memory命名规范

- `explore/{target}/endpoints` - 发现的端点
- `explore/{target}/vulns` - 发现的漏洞
- `explore/{target}/assets` - 内网资产
"""

def get_attack_system_prompt() -> str:
    """攻击Agent系统提示词"""
    return """
你是一个CTF攻击执行Agent，负责漏洞利用和后渗透操作。

## 执行前必做

1. **读取攻击计划**: mcp__serena__read_memory("plan/{target}/attack_plan")
2. **检查前置条件**: 确认所需凭据、会话已就绪
3. **评估风险**: 确认操作不会破坏目标

## 执行原则

1. **最小权限**: 只申请必要的权限
2. **超时控制**: 所有操作设置合理超时
3. **结果记录**: 攻击结果写入Memory
4. **错误处理**: 失败时记录原因并尝试备用方案

## Memory命名规范

- `attack/{target}/results` - 攻击结果
- `attack/{target}/credentials` - 获取的凭据
- `attack/{target}/flags` - 发现的Flag

## 安全边界

- 禁止: rm -rf, format, shutdown, reboot
- 需确认: 大规模扫描、敏感操作
"""
```

---

## 三、Agent间通信系统 (Serena Memory)

### 3.1 Memory命名规范

```
memory/
├── explore/
│   └── {target}/
│       ├── endpoints.md      # 发现的端点
│       ├── vulns.md          # 发现的漏洞
│       ├── assets.md         # 内网资产
│       └── code_analysis.md  # 代码分析结果
│
├── plan/
│   └── {target}/
│       ├── attack_plan.md    # 攻击计划
│       ├── vuln_chain.md     # 漏洞利用链
│       └── fallback.md       # 备选方案
│
├── attack/
│   └── {target}/
│       ├── results.md        # 攻击结果
│       ├── credentials.md    # 获取的凭据
│       └── flags.md          # 发现的Flag
│
├── verify/
│   └── {target}/
│       ├── verified_flags.md # 已验证的Flag
│       └── false_positives.md# 误报记录
│
└── global/
    ├── techniques/           # 通用技术
    ├── payloads/             # 通用Payload
    └── tools/                # 工具使用经验
```

### 3.2 Memory读写API

```python
class AgentMemorySystem:
    """
    Agent间通信系统
    
    基于serena MCP插件实现Agent间知识传递
    """
    
    def __init__(self, serena_client):
        self.serena = serena_client
    
    async def write_finding(
        self,
        agent_type: AgentType,
        target: str,
        topic: str,
        data: Dict
    ):
        """Agent写入发现"""
        memory_name = f"{agent_type.value}/{target}/{topic}"
        content = self._format_memory_content(data)
        
        await self.serena.write_memory(
            memory_name=memory_name,
            content=content
        )
    
    async def read_for_agent(
        self,
        agent_type: AgentType,
        topics: List[str]
    ) -> Dict[str, Any]:
        """Agent读取相关记忆"""
        memories = {}
        for topic in topics:
            try:
                content = await self.serena.read_memory(
                    memory_name=topic
                )
                if content:
                    memories[topic] = self._parse_memory(content)
            except Exception:
                pass
        return memories
    
    async def list_available_knowledge(
        self,
        agent_type: AgentType,
        target: str = None
    ) -> List[str]:
        """列出可用的知识库"""
        topic = f"{agent_type.value}"
        if target:
            topic += f"/{target}"
        
        memories = await self.serena.list_memories(topic=topic)
        return [m["name"] for m in memories]

# ============================================
# 使用示例
# ============================================

async def explore_to_attack_flow():
    """Explore → Attack 信息流转示例"""
    memory = AgentMemorySystem(serena_client)
    
    # 1. Explore Agent 写入发现
    await memory.write_finding(
        AgentType.EXPLORE,
        target="192.168.1.100",
        topic="vulns",
        data={
            "vulnerability": "SQLi",
            "endpoint": "/api/users?id=1",
            "param": "id",
            "payload_tested": "1' OR '1'='1"
        }
    )
    
    # 2. Plan Agent 读取并制定攻击计划
    vulns = await memory.read_for_agent(
        AgentType.PLAN,
        topics=["explore/192.168.1.100/vulns"]
    )
    
    attack_plan = plan_attack(vulns)
    
    await memory.write_finding(
        AgentType.PLAN,
        target="192.168.1.100",
        topic="attack_plan",
        data=attack_plan
    )
    
    # 3. Attack Agent 读取计划并执行
    plan = await memory.read_for_agent(
        AgentType.ATTACK,
        topics=["plan/192.168.1.100/attack_plan"]
    )
    
    result = execute_attack(plan)
    
    await memory.write_finding(
        AgentType.ATTACK,
        target="192.168.1.100",
        topic="results",
        data=result
    )
```

---

## 四、Prompt Cache共享机制 (Fork子Agent)

### 4.1 Fork机制原理

借鉴Claude Code的`buildForkedMessages`实现：

```python
from dataclasses import dataclass
from typing import List, Dict, Any
import uuid

FORK_PLACEHOLDER_RESULT = "[Previous tool result preserved for cache]"

@dataclass
class Message:
    role: str
    content: List[Dict]
    uuid: str = None

class PromptCacheManager:
    """
    Prompt Cache共享管理器
    
    核心原理：
    1. 克隆父Agent完整消息历史
    2. 为tool_use创建占位结果
    3. 确保API命中缓存
    """
    
    def build_forked_messages(
        self,
        directive: str,
        parent_messages: List[Message]
    ) -> List[Message]:
        """
        构建Fork子Agent的消息
        
        Args:
            directive: 子Agent任务指令
            parent_messages: 父Agent完整消息历史
        
        Returns:
            子Agent的消息列表，可命中Prompt Cache
        """
        # 1. 找到最后一个assistant消息
        last_assistant = None
        for msg in reversed(parent_messages):
            if msg.role == "assistant":
                last_assistant = msg
                break
        
        if not last_assistant:
            return [self._create_user_message(directive)]
        
        # 2. 克隆assistant消息
        forked_assistant = Message(
            role="assistant",
            content=[block.copy() for block in last_assistant.content],
            uuid=str(uuid.uuid4())
        )
        
        # 3. 为所有tool_use创建占位结果
        tool_result_blocks = []
        for block in forked_assistant.content:
            if block.get("type") == "tool_use":
                tool_result_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": block["id"],
                    "content": FORK_PLACEHOLDER_RESULT
                })
        
        # 4. 构建消息序列
        forked_messages = [
            forked_assistant,
            Message(
                role="user",
                content=tool_result_blocks + [{
                    "type": "text",
                    "text": f"[新任务] {directive}"
                }]
            )
        ]
        
        return forked_messages
    
    def fork_parallel_agents(
        self,
        targets: List[str],
        task_template: str,
        parent_messages: List[Message]
    ) -> List[Dict]:
        """
        并行派发多个Fork子Agent
        
        应用场景：
        - 并行扫描多个内网主机
        - Web CTF多路径探索
        
        Args:
            targets: 目标列表
            task_template: 任务模板
            parent_messages: 父Agent消息
        
        Returns:
            多个并行Agent任务
        """
        tasks = []
        for target in targets:
            directive = task_template.format(target=target)
            forked_messages = self.build_forked_messages(directive, parent_messages)
            
            tasks.append({
                "agent_type": "explore",
                "model": "glm-5",
                "messages": forked_messages,
                "inherit_cache": True,
                "target": target
            })
        
        return tasks

# ============================================
# 使用示例：并行内网扫描
# ============================================

async def parallel_internal_scan(
    internal_hosts: List[str],
    parent_context: List[Message]
):
    """并行扫描多个内网主机"""
    cache_manager = PromptCacheManager()
    
    # 创建共享上下文的并行任务
    tasks = cache_manager.fork_parallel_agents(
        targets=internal_hosts,
        task_template="扫描内网主机 {target}，发现开放端口和服务",
        parent_messages=parent_context
    )
    
    # 并行执行
    results = await coordinator.parallel_execute(tasks)
    
    # 汇总结果
    return aggregate_scan_results(results)
```

### 4.2 Fork vs Normal Spawn

| 特性 | Fork子Agent | Normal Spawn |
|------|-------------|--------------|
| 上下文继承 | 完整父Agent历史 | 从新消息开始 |
| Prompt Cache | 共享（字节级精确） | 独立构建 |
| Token开销 | 低（只传增量） | 高（完整上下文） |
| 适用场景 | 并行相似任务 | 独立复杂任务 |

---

## 五、Selector模式状态管理

### 5.1 SelectorStore实现

借鉴Claude Code的`useAppState(selector)`设计：

```python
from typing import Callable, TypeVar, Generic, Set
from dataclasses import dataclass, field
import threading

T = TypeVar('T')

@dataclass
class SelectorStore(Generic[T]):
    """
    选择器状态存储
    
    核心原理：
    1. 细粒度订阅 - 只订阅需要的状态切片
    2. 引用相等检查 - 避免不必要的更新
    3. 线程安全 - 支持多Agent并发
    """
    
    _state: T
    _listeners: Set[Callable] = field(default_factory=set)
    _selector_cache: Dict[Callable, Any] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def get_state(self) -> T:
        """获取完整状态"""
        return self._state
    
    def set_state(self, updater: Callable[[T], T]):
        """更新状态"""
        with self._lock:
            old_state = self._state
            new_state = updater(old_state)
            
            # 引用相等检查
            if new_state is old_state:
                return
            
            self._state = new_state
            
            # 通知相关监听器
            for listener in list(self._listeners):
                listener(new_state)
    
    def subscribe(
        self,
        selector: Callable[[T], Any],
        callback: Callable[[Any], None]
    ) -> Callable[[], None]:
        """
        订阅状态切片
        
        Args:
            selector: 状态选择器函数
            callback: 值变化时的回调
        
        Returns:
            取消订阅函数
        
        Example:
            store.subscribe(
                lambda s: s["credentials"],
                on_credentials_update
            )
        """
        def listener(new_state):
            new_value = selector(new_state)
            old_value = self._selector_cache.get(selector)
            
            # 只有选中值变化才触发回调
            if new_value != old_value:
                self._selector_cache[selector] = new_value
                callback(new_value)
        
        self._listeners.add(listener)
        
        # 初始化缓存
        self._selector_cache[selector] = selector(self._state)
        
        # 返回取消函数
        return lambda: self._listeners.discard(listener)

# ============================================
# CTF状态定义
# ============================================

@dataclass
class CTFStateV3:
    """CTF状态 V3"""
    # 任务信息
    task_id: str = ""
    task_name: str = ""
    target_url: str = ""
    
    # 探索结果 (Explore Agent)
    discovered_paths: List[str] = field(default_factory=list)
    discovered_endpoints: List[Dict] = field(default_factory=list)
    code_analysis: Dict = field(default_factory=dict)
    
    # 规划结果 (Plan Agent)
    attack_plan: Dict = field(default_factory=dict)
    vulnerability_hypotheses: List[Dict] = field(default_factory=list)
    
    # 攻击结果 (Attack Agent)
    attack_results: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)  # CRITICAL
    shell_sessions: List[Dict] = field(default_factory=list)  # CRITICAL
    
    # 验证结果 (Verify Agent)
    found_flags: List[str] = field(default_factory=list)  # CRITICAL
    verified_flags: List[str] = field(default_factory=list)
    
    # 内网资产 (Internal Network)
    internal_hosts: List[Dict] = field(default_factory=list)
    
    # 控制流
    current_phase: str = "explore"
    failure_score: float = 0.0
    iteration_count: int = 0

# ============================================
# 使用示例
# ============================================

def setup_state_subscriptions(store: SelectorStore[CTFStateV3]):
    """设置状态订阅"""
    
    # Explore Agent 只订阅路径发现
    store.subscribe(
        selector=lambda s: s.discovered_paths,
        callback=lambda paths: print(f"[Explore] 发现 {len(paths)} 个路径")
    )
    
    # Attack Agent 只订阅凭据和会话
    store.subscribe(
        selector=lambda s: s.credentials,
        callback=lambda creds: print(f"[Attack] 获取 {len(creds)} 个凭据")
    )
    
    # Verify Agent 只订阅Flag
    store.subscribe(
        selector=lambda s: s.found_flags,
        callback=lambda flags: print(f"[Verify] 发现 {len(flags)} 个Flag")
    )
    
    # Coordinator 订阅多个状态
    store.subscribe(
        selector=lambda s: {
            "hosts": len(s.internal_hosts),
            "flags": len(s.found_flags),
            "phase": s.current_phase
        },
        callback=lambda status: print(f"[Coordinator] {status}")
    )
```

### 5.2 Agent状态隔离

```python
class AgentStateView:
    """
    Agent状态视图
    
    为不同Agent提供定制化的状态视图
    """
    
    def __init__(
        self,
        store: SelectorStore[CTFStateV3],
        agent_type: AgentType
    ):
        self.store = store
        self.agent_type = agent_type
        self._subscriptions = []
    
    def get_visible_state(self) -> Dict:
        """获取该Agent可见的状态切片"""
        full_state = self.store.get_state()
        
        if self.agent_type == AgentType.EXPLORE:
            return {
                "task_id": full_state.task_id,
                "target_url": full_state.target_url,
                "discovered_paths": full_state.discovered_paths,
                "discovered_endpoints": full_state.discovered_endpoints
            }
        
        elif self.agent_type == AgentType.ATTACK:
            return {
                "task_id": full_state.task_id,
                "target_url": full_state.target_url,
                "attack_plan": full_state.attack_plan,
                "credentials": full_state.credentials,
                "shell_sessions": full_state.shell_sessions
            }
        
        elif self.agent_type == AgentType.VERIFY:
            return {
                "found_flags": full_state.found_flags,
                "attack_results": full_state.attack_results[-10:]  # 只看最近10条
            }
        
        return full_state  # Coordinator 可见全部
```

---

## 六、智能工具系统

### 6.1 buildTool工厂函数

借鉴Claude Code的`buildTool`设计：

```python
from dataclasses import dataclass
from typing import Dict, Any, Callable, List, Optional
from enum import Enum
import jsonschema

class ToolPermission(Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"

@dataclass
class ToolResult:
    """工具执行结果"""
    success: bool
    data: Any = None
    error: str = None
    raw_output: str = ""
    
    def to_dict(self) -> Dict:
        result = {"success": self.success}
        if self.data:
            result["data"] = self.data
        if self.error:
            result["error"] = self.error
        return result

# ============================================
# 默认值定义
# ============================================

TOOL_DEFAULTS = {
    "is_enabled": lambda: True,
    "is_concurrency_safe": lambda _: False,  # 保守策略
    "is_read_only": lambda _: False,
    "is_destructive": lambda _: False,
    "timeout": 300,
    "retry_count": 2
}

def build_tool(
    name: str,
    description: str,
    input_schema: Dict,
    handler: Callable,
    permissions: List[ToolPermission] = None,
    check_permissions: Callable = None,
    is_concurrency_safe: bool = False,
    is_read_only: bool = False,
    timeout: int = 300
) -> Dict:
    """
    工具工厂函数
    
    Args:
        name: 工具名称
        description: 功能描述（供LLM决策）
        input_schema: JSON Schema参数定义
        handler: 执行函数
        permissions: 所需权限列表
        check_permissions: 权限检查函数
        is_concurrency_safe: 是否并发安全
        is_read_only: 是否只读
        timeout: 超时时间
    
    Returns:
        完整的工具定义
    """
    
    async def wrapped_handler(params: Dict, context: Dict) -> ToolResult:
        """包装的执行函数"""
        
        # 1. Schema验证
        try:
            jsonschema.validate(params, input_schema)
        except jsonschema.ValidationError as e:
            return ToolResult(
                success=False,
                error=f"参数验证失败: {e.message}"
            )
        
        # 2. 权限检查
        if check_permissions:
            perm_result = check_permissions(context, permissions or [])
            if not perm_result.get("allowed"):
                return ToolResult(
                    success=False,
                    error=f"权限不足: {perm_result.get('reason')}"
                )
        
        # 3. 执行工具
        try:
            result = await handler(params, context)
            if isinstance(result, ToolResult):
                return result
            return ToolResult(success=True, data=result)
        except Exception as e:
            return ToolResult(success=False, error=str(e))
    
    return {
        "name": name,
        "description": description,
        "input_schema": input_schema,
        "handler": wrapped_handler,
        "permissions": permissions or [ToolPermission.READ],
        "is_concurrency_safe": is_concurrency_safe,
        "is_read_only": is_read_only,
        "timeout": timeout
    }

# ============================================
# 使用示例：SQLMap工具
# ============================================

sqlmap_tool = build_tool(
    name="sqlmap",
    description="SQL注入自动化利用工具。适用于：已识别SQL注入点、需要提取数据库信息",
    input_schema={
        "type": "object",
        "properties": {
            "target_url": {
                "type": "string",
                "format": "uri",
                "description": "目标URL"
            },
            "param": {
                "type": "string",
                "description": "注入参数名"
            },
            "level": {
                "type": "integer",
                "minimum": 1,
                "maximum": 5,
                "default": 1
            },
            "technique": {
                "type": "string",
                "enum": ["BEUSTQ", "B", "E", "U", "S", "T", "Q"],
                "default": "BEUSTQ"
            }
        },
        "required": ["target_url"]
    },
    handler=sqlmap_handler,
    permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK],
    is_concurrency_safe=False,
    is_read_only=False,
    timeout=600
)

async def sqlmap_handler(params: Dict, context: Dict) -> Dict:
    """SQLMap执行处理器"""
    # 实现省略
    pass
```

### 6.2 权限检查系统

```python
class PermissionChecker:
    """三层权限检查"""
    
    # Agent层权限
    AGENT_PERMISSIONS = {
        AgentType.EXPLORE: [ToolPermission.READ],
        AgentType.PLAN: [ToolPermission.READ],
        AgentType.ATTACK: [
            ToolPermission.READ,
            ToolPermission.WRITE,
            ToolPermission.EXECUTE,
            ToolPermission.NETWORK
        ],
        AgentType.VERIFY: [ToolPermission.READ, ToolPermission.EXECUTE],
        AgentType.COORDINATOR: [ToolPermission.READ]
    }
    
    # 工具层权限
    TOOL_PERMISSIONS = {
        "Bash(rm:*)": [],  # 禁止
        "Bash(sudo:*)": [ToolPermission.EXECUTE],
        "Write": [ToolPermission.WRITE],
        "Read": [ToolPermission.READ],
        "mcp__playwright__*": [ToolPermission.NETWORK],
        "mcp__serena__write_memory": [ToolPermission.WRITE]
    }
    
    def check(
        self,
        agent_type: AgentType,
        tool_name: str,
        context: Dict
    ) -> Dict:
        """三层权限检查"""
        
        # 1. Agent权限检查
        agent_perms = self.AGENT_PERMISSIONS.get(agent_type, [])
        
        # 2. 工具权限检查
        tool_perms = self._get_tool_permissions(tool_name)
        
        # 3. 上下文检查（如内网隔离）
        context_result = self._check_context(context, tool_name)
        
        # 交集检查
        allowed = all(
            p in agent_perms for p in tool_perms
        ) and context_result["allowed"]
        
        return {
            "allowed": allowed,
            "reason": "" if allowed else self._build_reason(
                agent_type, tool_name, agent_perms, tool_perms
            )
        }
    
    def _get_tool_permissions(self, tool_name: str) -> List[ToolPermission]:
        """获取工具所需权限"""
        # 精确匹配
        if tool_name in self.TOOL_PERMISSIONS:
            return self.TOOL_PERMISSIONS[tool_name]
        
        # 通配符匹配
        for pattern, perms in self.TOOL_PERMISSIONS.items():
            if "*" in pattern:
                prefix = pattern.replace("*", "")
                if tool_name.startswith(prefix):
                    return perms
        
        # 默认需要READ权限
        return [ToolPermission.READ]
```

---

## 七、智能上下文压缩

### 7.1 压缩策略

保留现有`context_compressor.py`并增强：

```python
class SmartCompressor:
    """
    智能上下文压缩器
    
    借鉴Claude Code的autoCompact + reactiveCompact
    """
    
    # 优先级定义
    PRIORITY = {
        # CRITICAL - 永不压缩
        "credentials": "CRITICAL",
        "found_flags": "CRITICAL",
        "shell_sessions": "CRITICAL",
        
        # HIGH - 保留结构
        "vulnerability_hypotheses": "HIGH",
        "attack_plan": "HIGH",
        "internal_hosts": "HIGH",
        
        # MEDIUM - 去重摘要
        "discovered_paths": "MEDIUM",
        "discovered_endpoints": "MEDIUM",
        "attack_results": "MEDIUM",
        
        # LOW - 大幅压缩
        "tool_calls": "LOW",
        "raw_output": "LOW"
    }
    
    def should_compress(self, token_count: int) -> bool:
        """判断是否需要压缩"""
        # 阈值检查
        if token_count > self.MAX_TOKENS * 0.8:
            return True
        
        # 趋势检查
        if self._get_growth_rate() > 0.1:  # 10%增长率
            return True
        
        return False
    
    def compress(self, state: CTFStateV3) -> CTFStateV3:
        """执行压缩"""
        compressed = CTFStateV3()
        
        for field, priority in self.PRIORITY.items():
            value = getattr(state, field, None)
            if value is None:
                continue
            
            if priority == "CRITICAL":
                # 完整保留
                setattr(compressed, field, value)
            
            elif priority == "HIGH":
                # 保留结构，截断详情
                setattr(compressed, field, self._truncate_high(value))
            
            elif priority == "MEDIUM":
                # 去重摘要
                setattr(compressed, field, self._dedupe_medium(value))
            
            else:  # LOW
                # 只保留统计
                setattr(compressed, field, self._summarize_low(value))
        
        return compressed
    
    def _truncate_high(self, value: Any) -> Any:
        """HIGH优先级截断"""
        if isinstance(value, list):
            return value[:20]  # 保留前20条
        elif isinstance(value, dict):
            return {
                k: v[:200] if isinstance(v, str) else v
                for k, v in list(value.items())[:20]
            }
        return value
    
    def _dedupe_medium(self, value: Any) -> Any:
        """MEDIUM优先级去重"""
        if isinstance(value, list):
            seen = set()
            unique = []
            for item in value:
                key = self._get_dedupe_key(item)
                if key not in seen:
                    seen.add(key)
                    unique.append(item)
            return unique[:50]  # 最多50条
        return value
    
    def _summarize_low(self, value: Any) -> Any:
        """LOW优先级摘要"""
        if isinstance(value, list):
            return {
                "count": len(value),
                "success_count": sum(1 for v in value if v.get("success")),
                "failed_count": sum(1 for v in value if not v.get("success"))
            }
        return {"present": True}
```

### 7.2 自动压缩触发

```python
class AutoCompactTrigger:
    """自动压缩触发器"""
    
    def __init__(self, compressor: SmartCompressor):
        self.compressor = compressor
        self.last_token_count = 0
    
    def check_and_compact(
        self,
        state: CTFStateV3,
        token_count: int
    ) -> Tuple[CTFStateV3, bool]:
        """
        检查并执行压缩
        
        Returns:
            (compressed_state, was_compacted)
        """
        # 检查是否需要压缩
        if not self.compressor.should_compress(token_count):
            return state, False
        
        # 检查增长趋势
        growth = (token_count - self.last_token_count) / max(self.last_token_count, 1)
        
        # 快速增长时提前压缩
        if growth > 0.2:  # 20%增长
            print(f"[AutoCompact] 检测到快速增长 {growth:.1%}，触发压缩")
            compressed = self.compressor.compress(state)
            self.last_token_count = token_count
            return compressed, True
        
        # 常规压缩
        if token_count > self.compressor.MAX_TOKENS * 0.8:
            print(f"[AutoCompact] Token超过阈值，触发压缩")
            compressed = self.compressor.compress(state)
            self.last_token_count = token_count
            return compressed, True
        
        self.last_token_count = token_count
        return state, False
```

---

## 八、Coordinator模式实现

### 8.1 协调者系统提示词

```python
def get_coordinator_system_prompt() -> str:
    """协调者Agent系统提示词"""
    return """
你是一个CTF协调者Agent，负责调度多个Agent完成复杂任务。

## 1. 你的角色

- **任务分解**: 将复杂任务分解为子任务
- **Agent派发**: 选择合适的Agent类型执行子任务
- **并行调度**: 同时派发多个Agent处理独立任务
- **结果综合**: 汇总各Agent的结果

## 2. 可用工具

- **Agent**: 派发子Agent
- **mcp__serena__read_memory**: 读取Agent知识
- **mcp__serena__write_memory**: 写入协调决策
- **AskUserQuestion**: 请求用户决策

## 3. Agent类型选择

| 场景 | Agent类型 | 说明 |
|------|-----------|------|
| 信息收集 | Explore | 只读，快速 |
| 攻击规划 | Plan | 只读，架构分析 |
| 漏洞利用 | Attack | 读写执行 |
| 结果验证 | Verify | 独立验证 |

## 4. 并行调度原则

**并行是你的超能力！**

- 多个独立目标 → 并行Explore Agent
- 多个漏洞 → 并行Attack Agent
- 攻击结果 → 立即派发Verify Agent

## 5. 知识管理

- 使用Memory系统共享知识
- Explore发现 → 写入 `explore/{target}/`
- Plan制定 → 写入 `plan/{target}/`
- Attack结果 → 写入 `attack/{target}/`
"""
```

### 8.2 并行调度实现

```python
class CoordinatorDispatcher:
    """协调者调度器"""
    
    def __init__(
        self,
        agent_registry: Dict[AgentType, AgentDefinition],
        memory_system: AgentMemorySystem
    ):
        self.agents = agent_registry
        self.memory = memory_system
        self.active_tasks: Dict[str, asyncio.Task] = {}
    
    async def dispatch_parallel(
        self,
        tasks: List[Dict]
    ) -> List[Dict]:
        """
        并行派发多个Agent
        
        Args:
            tasks: 任务列表，每个任务包含:
                - agent_type: Agent类型
                - target: 目标
                - directive: 任务指令
                - inherit_cache: 是否继承缓存
        
        Returns:
            所有任务的结果
        """
        async def run_task(task):
            task_id = str(uuid.uuid4())
            agent_type = task["agent_type"]
            directive = task["directive"]
            
            # 创建Agent任务
            agent_task = asyncio.create_task(
                self._run_agent(
                    agent_type=agent_type,
                    directive=directive,
                    inherit_cache=task.get("inherit_cache", False)
                )
            )
            
            self.active_tasks[task_id] = agent_task
            
            try:
                result = await agent_task
                return {"task_id": task_id, "success": True, "result": result}
            except Exception as e:
                return {"task_id": task_id, "success": False, "error": str(e)}
            finally:
                del self.active_tasks[task_id]
        
        # 并行执行所有任务
        results = await asyncio.gather(*[run_task(t) for t in tasks])
        return list(results)
    
    async def dispatch_sequential(
        self,
        tasks: List[Dict],
        stop_on_success: bool = False
    ) -> List[Dict]:
        """
        顺序派发Agent
        
        Args:
            tasks: 任务列表
            stop_on_success: 成功后是否停止
        """
        results = []
        
        for task in tasks:
            result = await self._run_agent(
                agent_type=task["agent_type"],
                directive=task["directive"]
            )
            results.append(result)
            
            if stop_on_success and result.get("success"):
                break
        
        return results
    
    async def _run_agent(
        self,
        agent_type: AgentType,
        directive: str,
        inherit_cache: bool = False
    ) -> Dict:
        """执行单个Agent"""
        # 实现Agent执行逻辑
        pass

# ============================================
# 使用示例：并行内网扫描
# ============================================

async def coordinate_internal_penetration(
    internal_hosts: List[str],
    coordinator: CoordinatorDispatcher
):
    """协调内网渗透"""
    
    # Phase 1: 并行探索
    explore_tasks = [
        {
            "agent_type": AgentType.EXPLORE,
            "target": host,
            "directive": f"探索内网主机 {host}，发现开放端口和服务",
            "inherit_cache": True  # 共享Prompt Cache
        }
        for host in internal_hosts
    ]
    
    explore_results = await coordinator.dispatch_parallel(explore_tasks)
    
    # Phase 2: 根据发现制定攻击计划
    for result in explore_results:
        if result["success"] and result["result"].get("vulns"):
            # 派发Plan Agent
            await coordinator._run_agent(
                agent_type=AgentType.PLAN,
                directive=f"为 {result['target']} 制定攻击计划"
            )
    
    # Phase 3: 并行攻击
    attack_tasks = [
        {
            "agent_type": AgentType.ATTACK,
            "target": host,
            "directive": f"执行对 {host} 的攻击"
        }
        for host in get_vulnerable_hosts(explore_results)
    ]
    
    attack_results = await coordinator.dispatch_parallel(attack_tasks)
    
    # Phase 4: 验证
    verify_tasks = [
        {
            "agent_type": AgentType.VERIFY,
            "directive": f"验证 {result['target']} 的攻击结果"
        }
        for result in attack_results if result["success"]
    ]
    
    verify_results = await coordinator.dispatch_parallel(verify_tasks)
    
    return {
        "explored": len(explore_results),
        "attacked": len(attack_results),
        "verified": len(verify_results),
        "flags": extract_flags(verify_results)
    }
```

---

## 九、实施计划

### 9.1 阶段划分

```
Phase 1: 基础架构 (Week 1-2)
├── Agent类型系统实现
│   ├── AgentDefinition数据类
│   ├── Agent权限检查
│   └── Agent系统提示词
├── SelectorStore实现
└── 单元测试

Phase 2: 通信系统 (Week 3-4)
├── AgentMemorySystem实现
├── Serena Memory集成
├── Prompt Cache管理器
└── 集成测试

Phase 3: 工具系统 (Week 5-6)
├── buildTool工厂
├── Zod Schema验证
├── 权限检查器
├── MCP工具迁移
└── 回归测试

Phase 4: 协调系统 (Week 7-8)
├── Coordinator实现
├── 并行调度
├── 上下文压缩增强
└── 端到端测试

Phase 5: 迁移与优化 (Week 9-10)
├── Web CTF模块迁移
├── 内网渗透模块迁移
├── 性能优化
└── 文档编写
```

### 9.2 文件清单

**新增文件**:
```
app/
├── agents/
│   ├── __init__.py
│   ├── base.py                  # AgentDefinition, AgentType
│   ├── explore_agent.py
│   ├── plan_agent.py
│   ├── attack_agent.py
│   ├── verify_agent.py
│   └── coordinator.py
├── memory/
│   ├── __init__.py
│   ├── agent_memory.py          # AgentMemorySystem
│   ├── prompt_cache.py          # PromptCacheManager
│   └── memory_naming.py         # Memory命名规范
├── state/
│   ├── __init__.py
│   ├── selector_store.py        # SelectorStore
│   ├── state_v3.py              # CTFStateV3
│   └── agent_view.py            # AgentStateView
├── tools/
│   ├── __init__.py
│   ├── tool_factory.py          # buildTool
│   ├── schema_validator.py      # Zod风格验证
│   └── permission_checker.py    # 三层权限检查
├── coordinator/
│   ├── __init__.py
│   ├── dispatcher.py            # CoordinatorDispatcher
│   └── prompts.py               # 协调者提示词
└── compressor/
    ├── __init__.py
    ├── smart_compressor.py      # SmartCompressor
    └── auto_compact.py          # AutoCompactTrigger
```

---

## 十、验收标准

### 10.1 功能验收

- [ ] 五类Agent可正常派发任务
- [ ] Agent间通过Memory正确通信
- [ ] Prompt Cache在并行任务中生效
- [ ] Selector模式正确触发订阅
- [ ] buildTool创建的工具通过验证
- [ ] 权限检查正确拦截越权
- [ ] Coordinator可并行调度多Agent
- [ ] 上下文压缩按预期工作

### 10.2 性能验收

- [ ] Explore Agent响应 < 30s
- [ ] 8个并行Agent无阻塞
- [ ] Token消耗降低 > 40%
- [ ] 内存占用 < 2GB

### 10.3 质量验收

- [ ] 单元测试覆盖率 > 80%
- [ ] 集成测试通过率 > 95%
- [ ] 无高危安全漏洞

---

**文档状态**: 已批准  
**下一步**: 开始Phase 1实现