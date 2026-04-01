---
name: CTF-Agent 深度重构设计
description: 基于 Claude Code CLI 设计模式的 CTF-Agent 2.0 架构重构方案
type: project
version: 2.0
date: 2026-04-01
status: draft
---

# CTF-Agent 2.0 深度重构设计文档

## 一、执行摘要

### 1.1 重构目标

将 CTF-Agent 从现有架构升级为基于 **Claude Code CLI** 设计模式的下一代智能渗透测试框架，实现：

- **分层Agent架构**: 引入 Explore/Plan/Attack/Verify 四类Agent
- **Fork子Agent机制**: Prompt Cache共享的高效并行执行
- **MCP插件系统**: 标准化工具扩展接口
- **状态机驱动**: 基于LangGraph的可靠执行流程

### 1.2 核心改进

| 现有问题 | 重构方案 | 预期收益 |
|---------|---------|---------|
| 单一LLM调用模式 | 分层Agent类型 | 成本降低40%+ |
| 工具注册缺乏验证 | Zod Schema校验 | 错误减少80% |
| 无并行执行能力 | Fork子Agent机制 | 效率提升3x |
| 模块耦合度高 | MCP解耦架构 | 可维护性提升 |

---

## 二、架构设计

### 2.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        CTF-Agent 2.0                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐│
│  │  Coordinator │  │  StateGraph │  │  Checkpoint │  │  MCP    ││
│  │   Mode      │  │   Engine    │  │   Memory    │  │ Manager ││
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────┬────┘│
│         │                │                │              │      │
│  ┌──────▼────────────────▼────────────────▼──────────────▼────┐│
│  │                    Agent Dispatch Layer                     ││
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐ ││
│  │  │Explore │ │  Plan  │ │ Attack │ │ Verify │ │  General │ ││
│  │  │ Agent  │ │ Agent  │ │ Agent  │ │ Agent  │ │  Agent   │ ││
│  │  │(glm-5) │ │(glm-5) │ │(glm-5) │ │(glm-5) │ │ (glm-5)  │ ││
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └──────────┘ ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│  ┌───────────────────────────▼─────────────────────────────────┐│
│  │                    Tool System Layer                         ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  ││
│  │  │ ToolRegistry │  │ ZodValidator │  │ PermissionSystem │  ││
│  │  │  (Singleton) │  │  (Schema)    │  │   (checkPerms)   │  ││
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│  ┌───────────────────────────▼─────────────────────────────────┐│
│  │                    MCP Plugin Layer                          ││
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────┐ ││
│  │  │ Serena  │ │ Semgrep │ │Context7 │ │Playwright│ │Figma │ ││
│  │  │  (LSP)  │ │ (Scan)  │ │  (Docs) │ │ (Browser)│ │(Design)│ ││
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └───────┘ ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Agent类型系统

基于Claude Code的分层Agent设计：

#### 2.2.1 Explore Agent (探索型)

```python
class ExploreAgentConfig:
    """只读探索Agent - 用于信息收集和代码分析"""
    model: str = "glm-5"  # 成本优化
    read_only: bool = True
    allowed_tools: List[str] = [
        "Read", "Glob", "Grep", "LSP",
        "WebFetch", "WebSearch",
        "mcp__serena__find_symbol",
        "mcp__serena__get_symbols_overview"
    ]
    denied_tools: List[str] = ["Edit", "Write", "Bash"]
    max_context_tokens: int = 50000
    timeout: int = 120  # 秒
```

**Why**: Claude Code使用Haiku模型进行只读探索，成本仅为Sonnet的1/10。CTF场景中大量信息收集工作（目录扫描、代码审计）适合此模式。

**How to apply**: 
- Web CTF Recon阶段 → Explore Agent
- 内网信息收集 → Explore Agent
- 代码审计分析 → Explore Agent

#### 2.2.2 Plan Agent (规划型)

```python
class PlanAgentConfig:
    """架构规划Agent - 用于设计攻击方案"""
    model: str = "glm-5"
    read_only: bool = True
    allowed_tools: List[str] = [
        "Read", "Glob", "Grep", "LSP",
        "WebFetch", "WebSearch", "AskUserQuestion",
        "EnterPlanMode", "ExitPlanMode"
    ]
    denied_tools: List[str] = ["Edit", "Write", "Bash"]
    planning_horizon: int = 10  # 规划深度
```

**Why**: 规划需要更强的推理能力但不需写权限。分离规划与执行防止误操作。

**How to apply**:
- 攻击策略制定 → Plan Agent
- 漏洞利用链设计 → Plan Agent
- 内网渗透路径规划 → Plan Agent

#### 2.2.3 Attack Agent (攻击型)

```python
class AttackAgentConfig:
    """攻击执行Agent - 执行渗透测试任务"""
    model: str = "glm-5"
    read_only: bool = False
    allowed_tools: List[str] = [
        "Read", "Write", "Edit", "Bash",
        "mcp__playwright__browser_click",
        "mcp__playwright__browser_navigate",
        "mcp__semgrep__semgrep_scan"
    ]
    denied_tools: List[str] = [
        "Bash(rm -rf /*)", "Bash(sudo rm:*)",
        "Bash(format:*)", "Bash(shutdown:*)"
    ]
    max_concurrent_tasks: int = 8
```

**Why**: 攻击操作需要写权限和工具执行能力，但需安全边界限制危险操作。

**How to apply**:
- 漏洞利用执行 → Attack Agent
- 后渗透操作 → Attack Agent
- 工具调用 → Attack Agent

#### 2.2.4 Verify Agent (验证型)

```python
class VerifyAgentConfig:
    """验证Agent - 对抗性测试结果"""
    model: str = "glm-5"
    read_only: bool = False
    adversarial_mode: bool = True
    allowed_tools: List[str] = [
        "Read", "Bash", "Grep",
        "mcp__semgrep__semgrep_scan",
        "mcp__semgrep__semgrep_findings"
    ]
    verification_criteria: List[str] = [
        "flag_format_valid",
        "vulnerability_reproducible",
        "no_false_positive"
    ]
```

**Why**: 独立验证确保攻击结果可靠性，对抗模式发现遗漏问题。

**How to apply**:
- Flag有效性验证 → Verify Agent
- 漏洞可复现性检查 → Verify Agent
- 误报过滤 → Verify Agent

### 2.3 Fork子Agent机制

**Why**: Prompt Cache共享机制允许子Agent继承父Agent上下文，避免重复传输大Token。

```python
class ForkSubagentManager:
    """
    Fork子Agent管理器
    
    设计原理:
    - 父Agent创建子Agent时共享Prompt Cache
    - 子Agent独立执行但复用上下文
    - 结果聚合到父Agent状态
    """
    
    def fork_explore_agents(self, targets: List[str]) -> List[AgentTask]:
        """并行派发多个Explore Agent"""
        tasks = []
        for target in targets:
            task = AgentTask(
                agent_type="explore",
                model="glm-5",
                prompt=f"探索目标: {target}",
                inherit_cache=True,  # 关键：继承Prompt Cache
                isolation="worktree"  # 可选：隔离工作目录
            )
            tasks.append(task)
        return self.dispatcher.parallel_execute(tasks)
```

**How to apply**:
```python
# 场景：并行扫描多个内网主机
internal_hosts = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
results = fork_subagent_manager.fork_explore_agents(internal_hosts)
```

---

## 三、工具系统重构

### 3.1 buildTool工厂模式

**Why**: Claude Code使用工厂模式统一创建工具，确保Schema一致性和权限分离。

```python
from dataclasses import dataclass
from typing import Callable, Dict, Any, List
from enum import Enum

class ToolPermission(Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"

@dataclass
class ToolSchema:
    """Zod风格的Schema定义"""
    name: str
    description: str
    parameters: Dict[str, Any]  # JSON Schema
    permissions: List[ToolPermission]
    timeout: int = 300
    retry_count: int = 2

def buildTool(
    name: str,
    description: str,
    parameters: Dict[str, Any],
    handler: Callable,
    permissions: List[ToolPermission] = None,
    check_permissions: Callable = None
) -> Dict:
    """
    工具工厂函数
    
    Args:
        name: 工具名称
        description: 功能描述（供LLM决策）
        parameters: 参数Schema（JSON Schema格式）
        handler: 执行函数
        permissions: 所需权限列表
        check_permissions: 权限检查函数
    
    Returns:
        完整的工具定义字典
    """
    schema = ToolSchema(
        name=name,
        description=description,
        parameters=parameters,
        permissions=permissions or [ToolPermission.READ]
    )
    
    async def wrapped_handler(params: Dict, context: Dict) -> Dict:
        # 1. Schema验证
        validated = validate_params(params, schema.parameters)
        
        # 2. 权限检查
        if check_permissions:
            perm_result = check_permissions(context, schema.permissions)
            if not perm_result.allowed:
                return {"error": f"Permission denied: {perm_result.reason}"}
        
        # 3. 执行工具
        try:
            result = await handler(validated, context)
            return ensure_result_format(result)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    return {
        "name": name,
        "description": description,
        "parameters": parameters,
        "handler": wrapped_handler,
        "schema": schema
    }
```

### 3.2 Zod Schema验证

**Why**: 运行时类型验证防止参数注入和格式错误。

```python
from typing import get_type_hints
import jsonschema
from functools import wraps

def zod_validate(schema: Dict):
    """Zod风格的装饰器验证"""
    def decorator(func):
        @wraps(func)
        async def wrapper(params: Dict, *args, **kwargs):
            try:
                jsonschema.validate(params, schema)
            except jsonschema.ValidationError as e:
                return {
                    "success": False,
                    "error": f"参数验证失败: {e.message}",
                    "schema_path": list(e.absolute_path)
                }
            return await func(params, *args, **kwargs)
        return wrapper
    return decorator

# 示例：SQLMap工具定义
@zod_validate({
    "type": "object",
    "properties": {
        "target_url": {"type": "string", "format": "uri"},
        "level": {"type": "integer", "minimum": 1, "maximum": 5},
        "technique": {"type": "string", "enum": ["BEUSTQ", "B", "E", "U", "S", "T", "Q"]}
    },
    "required": ["target_url"]
})
async def sqlmap_handler(params: Dict, context: Dict) -> Dict:
    # 参数已验证，直接执行
    ...
```

### 3.3 权限分离系统

**Why**: 分层权限防止权限提升攻击，符合最小权限原则。

```python
class PermissionChecker:
    """权限检查器 - 三层权限模型"""
    
    # Agent层权限
    AGENT_PERMISSIONS = {
        "explore": [ToolPermission.READ],
        "plan": [ToolPermission.READ],
        "attack": [ToolPermission.READ, ToolPermission.WRITE, ToolPermission.EXECUTE],
        "verify": [ToolPermission.READ, ToolPermission.EXECUTE]
    }
    
    # 工具层权限
    TOOL_PERMISSIONS = {
        "Bash(rm:*)": [],  # 禁止
        "Bash(sudo:*)": [ToolPermission.EXECUTE],  # 需要执行权限
        "Write": [ToolPermission.WRITE],
        "Read": [ToolPermission.READ]
    }
    
    def check(self, agent_type: str, tool_name: str, context: Dict) -> PermissionResult:
        """三层权限检查"""
        # 1. Agent权限检查
        agent_perms = self.AGENT_PERMISSIONS.get(agent_type, [])
        
        # 2. 工具权限检查
        tool_perms = self.TOOL_PERMISSIONS.get(tool_name, [ToolPermission.READ])
        
        # 3. 上下文检查（如内网隔离）
        context_check = self._check_context(context, tool_name)
        
        # 交集检查
        allowed = all(p in agent_perms for p in tool_perms) and context_check.allowed
        
        return PermissionResult(
            allowed=allowed,
            reason="" if allowed else f"Agent '{agent_type}' 缺少权限: {tool_perms}"
        )
```

---

## 四、状态管理与查询引擎

### 4.1 状态机驱动流程

**Why**: LangGraph状态机确保执行流程可靠，支持中断恢复。

```python
from langgraph.graph import StateGraph, END
from typing import TypedDict, Annotated
import operator

class CTFStateV3(TypedDict):
    """CTF状态 - V3重构版"""
    # 任务信息
    task_id: str
    task_name: str
    target_url: str
    
    # 探索结果 (Explore Agent)
    discovered_paths: Annotated[List[str], operator.add]
    discovered_params: Annotated[List[Dict], operator.add]
    code_analysis: Dict
    
    # 规划结果 (Plan Agent)
    attack_plan: Dict
    vulnerability_hypotheses: Annotated[List[Dict], operator.add]
    
    # 攻击结果 (Attack Agent)
    attack_results: Annotated[List[Dict], operator.add]
    vulnerabilities: Annotated[List[Dict], operator.add]
    flags: Annotated[List[str], operator.add]
    
    # 验证结果 (Verify Agent)
    verified_flags: Annotated[List[str], operator.add]
    false_positives: Annotated[List[str], operator.add]
    
    # 控制流
    current_phase: str
    failure_score: float
    iteration_count: int

def build_ctf_graph() -> StateGraph:
    """构建CTF状态图"""
    graph = StateGraph(CTFStateV3)
    
    # 添加节点
    graph.add_node("detect_type", challenge_type_detector_node)
    graph.add_node("explore", explore_node)
    graph.add_node("plan", plan_node)
    graph.add_node("attack", attack_node)
    graph.add_node("verify", verify_node)
    graph.add_node("evolve", evolution_node)
    
    # 定义边
    graph.set_entry_point("detect_type")
    
    graph.add_edge("detect_type", "explore")
    graph.add_edge("explore", "plan")
    graph.add_edge("plan", "attack")
    graph.add_edge("attack", "verify")
    
    # 条件边
    graph.add_conditional_edges(
        "verify",
        route_after_verify,
        {
            "found_flag": END,
            "continue_attack": "attack",
            "need_innovation": "evolve",
            "abandon": END
        }
    )
    
    graph.add_edge("evolve", "plan")
    
    return graph.compile(checkpointer=MemorySaver())
```

### 4.2 AsyncGenerator流式输出

**Why**: 流式输出改善用户体验，支持长时间任务。

```python
from typing import AsyncGenerator
from enum import Enum

class StreamEventType(Enum):
    NODE_START = "node_start"
    NODE_RESULT = "node_result"
    TOOL_CALL = "tool_call"
    FLAG_FOUND = "flag_found"
    ERROR = "error"

async def execute_ctf_task(
    task: Dict,
    checkpoint_id: str = None
) -> AsyncGenerator[Dict, None]:
    """
    流式执行CTF任务
    
    Yields:
        事件流，支持前端实时渲染
    """
    graph = build_ctf_graph()
    state = init_state(task)
    
    async for event in graph.astream(state, checkpoint_id):
        event_type = event.get("type")
        node_name = event.get("node")
        data = event.get("data", {})
        
        # 流式输出事件
        yield {
            "type": StreamEventType(event_type),
            "node": node_name,
            "data": data,
            "timestamp": time.time()
        }
        
        # Flag发现时特殊处理
        if data.get("flags"):
            yield {
                "type": StreamEventType.FLAG_FOUND,
                "flags": data["flags"],
                "node": node_name
            }
```

---

## 五、MCP插件集成

### 5.1 MCP架构适配

**Why**: MCP协议提供标准化工具扩展接口，支持多种传输方式。

```python
from mcp import MCPServer, MCPTool
from typing import Dict, Any

class CTFMCPManager:
    """CTF MCP插件管理器"""
    
    def __init__(self):
        self.servers: Dict[str, MCPServer] = {}
        self.tools: Dict[str, MCPTool] = {}
    
    async def register_security_tools(self):
        """注册安全相关MCP工具"""
        
        # 1. Semgrep - 代码扫描
        await self.register_server("semgrep", {
            "type": "stdio",
            "command": "semgrep",
            "args": ["mcp"]
        })
        
        # 2. Serena - LSP代码分析
        await self.register_server("serena", {
            "type": "stdio",
            "command": "serena",
            "args": ["mcp"]
        })
        
        # 3. Context7 - 文档查询
        await self.register_server("context7", {
            "type": "http",
            "url": "https://api.context7.com/mcp"
        })
        
        # 4. Playwright - 浏览器自动化
        await self.register_server("playwright", {
            "type": "sdk",
            "module": "playwright.mcp"
        })
    
    async def execute_tool(
        self,
        tool_name: str,
        params: Dict,
        agent_type: str
    ) -> Dict:
        """通过MCP执行工具"""
        # 权限检查
        if not self.permission_checker.check(agent_type, tool_name, params):
            return {"error": "Permission denied"}
        
        # MCP调用
        server_name = self.tool_to_server[tool_name]
        result = await self.servers[server_name].call_tool(tool_name, params)
        
        return result
```

### 5.2 内置MCP工具映射

| MCP插件 | 功能 | 适用Agent | CTF场景 |
|---------|------|-----------|---------|
| serena | LSP代码分析 | Explore, Plan | 代码审计、漏洞定位 |
| semgrep | 静态扫描 | Explore, Verify | 漏洞模式匹配、误报过滤 |
| context7 | 文档查询 | Plan, Attack | 漏洞POC查询、技术文档 |
| playwright | 浏览器自动化 | Attack | XSS验证、CSRF测试 |
| chrome-devtools | 调试工具 | Attack, Verify | 前端漏洞利用 |

---

## 六、重构实施计划

### 6.1 阶段划分

```
Phase 1: 基础架构 (Week 1-2)
├── Agent类型系统实现
├── buildTool工厂模式
├── 权限分离系统
└── 单元测试

Phase 2: 核心重构 (Week 3-4)
├── 状态机迁移
├── MCP插件适配
├── 流式输出
└── 集成测试

Phase 3: 功能迁移 (Week 5-6)
├── Web CTF模块迁移
├── 内网渗透模块迁移
├── 其他CTF类型迁移
└── 回归测试

Phase 4: 优化与文档 (Week 7-8)
├── 性能优化
├── 文档编写
├── 示例代码
└── 发布准备
```

### 6.2 关键文件清单

**新增文件**:
```
app/
├── agents/
│   ├── __init__.py
│   ├── base_agent.py          # Agent基类
│   ├── explore_agent.py       # 探索Agent
│   ├── plan_agent.py          # 规划Agent
│   ├── attack_agent.py        # 攻击Agent
│   └── verify_agent.py        # 验证Agent
├── tools/
│   ├── tool_factory.py        # buildTool工厂
│   ├── schema_validator.py    # Zod验证器
│   └── permission_checker.py  # 权限检查器
├── mcp/
│   ├── mcp_manager.py         # MCP管理器
│   └── tool_mappings.py       # 工具映射
└── graph/
    ├── ctf_graph_v3.py        # 新版状态图
    └── state_v3.py            # 新版状态定义
```

**修改文件**:
```
app/
├── ctf_agent_graph.py         # 主入口重构
├── tool_framework.py          # 工具框架升级
├── module_registry.py         # 模块注册增强
└── config.py                  # 配置更新
```

### 6.3 配置更新

**config.yaml** 新增:
```yaml
# Agent类型配置
AGENT_TYPES:
  explore:
    model: glm-5
    read_only: true
    timeout: 120
  plan:
    model: glm-5
    read_only: true
    timeout: 180
  attack:
    model: glm-5
    read_only: false
    timeout: 600
  verify:
    model: glm-5
    read_only: false
    timeout: 300

# MCP配置
MCP_SERVERS:
  - name: semgrep
    type: stdio
    enabled: true
  - name: serena
    type: stdio
    enabled: true
  - name: context7
    type: http
    enabled: true
  - name: playwright
    type: sdk
    enabled: true
```

---

## 七、风险与缓解

### 7.1 技术风险

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| Agent类型误用 | 执行失败 | 运行时类型检查、单元测试覆盖 |
| MCP插件兼容性 | 功能缺失 | 渐进式迁移、兼容层封装 |
| 状态机死锁 | 任务卡住 | 超时机制、人工干预接口 |
| 并发竞争 | 数据不一致 | 分布式锁、乐观并发控制 |

### 7.2 回滚策略

```python
class FeatureFlag:
    """特性开关 - 支持灰度发布和回滚"""
    
    FLAGS = {
        "use_agent_types": True,      # 启用分层Agent
        "use_mcp_tools": False,       # MCP工具（灰度中）
        "use_fork_subagent": False,   # Fork子Agent（开发中）
        "legacy_tool_framework": True # 旧工具框架（兼容）
    }
    
    @classmethod
    def is_enabled(cls, flag: str) -> bool:
        return cls.FLAGS.get(flag, False)
```

---

## 八、验收标准

### 8.1 功能验收

- [ ] 所有Agent类型可正常派发任务
- [ ] buildTool创建的工具通过Schema验证
- [ ] 权限检查正确拦截越权操作
- [ ] MCP插件可通过统一接口调用
- [ ] 状态机可从任意检查点恢复
- [ ] 流式输出正常工作

### 8.2 性能验收

- [ ] Explore Agent响应时间 < 30s
- [ ] 并行执行8个子Agent无阻塞
- [ ] 内存占用 < 2GB（单任务）
- [ ] Token消耗降低 > 30%

### 8.3 质量验收

- [ ] 单元测试覆盖率 > 80%
- [ ] 集成测试通过率 > 95%
- [ ] 无高危安全漏洞
- [ ] 文档完整度 > 90%

---

## 九、附录

### A. 参考资料

1. Claude Code CLI 源码分析
2. LangGraph 官方文档
3. MCP协议规范
4. OWASP Top 10

### B. 术语表

| 术语 | 定义 |
|------|------|
| Fork子Agent | 从父Agent派生的独立执行单元，共享Prompt Cache |
| Prompt Cache | LLM上下文缓存，避免重复传输 |
| MCP | Model Context Protocol，模型上下文协议 |
| Zod Schema | TypeScript运行时类型验证库 |

### C. 变更日志

| 日期 | 版本 | 变更内容 |
|------|------|----------|
| 2026-04-01 | 1.0 | 初始设计文档 |

---

**文档状态**: 待审核  
**下一步**: 用户审核 → 创建实现计划 → 开始Phase 1实现