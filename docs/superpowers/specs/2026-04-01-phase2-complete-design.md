# CTF-Agent 2.0 Phase 2 完整设计文档

**版本**: 2.0  
**日期**: 2026-04-01  
**状态**: 待审核  

---

## 一、设计目标

### 1.1 核心目标

将CTF-Agent从预定义流程升级为**完全自主的多Agent系统**，借鉴Claude Code的设计：

1. **完全自主** - 输入目标地址，系统自主完成攻击，无需人工干预
2. **能力驱动** - Agent根据任务动态选择工具和技能
3. **知识复用** - Skill系统提供领域专业知识
4. **Token优化** - Prompt Cache共享，节省90%上下文传输

### 1.2 设计决策

| 决策点 | 选择 | 理由 |
|--------|------|------|
| 迁移策略 | 模块优先迭代 | 每个模块独立验证，问题早发现 |
| 自主程度 | 混合模式 | 核心自主 + 边界兜底 |
| Coordinator角色 | 监督者 | 调度 + 监控 + 干预 |
| 工具环境 | 无浏览器 | HTTP/命令行工具为主 |
| 部署方式 | 混合部署 | 核心裸机 + 工具容器化 |

---

## 二、架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CTF-Agent 2.0 系统架构                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    CLI展示层（非交互）                        │   │
│  │  - 日志输出（Agent行为、工具调用、发现）                      │   │
│  │  - 状态展示（当前阶段、进度、Token消耗）                      │   │
│  │  - 结果输出（Flag、攻击路径、报告）                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Coordinator监督层                         │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌──────────┐ │   │
│  │  │ 任务派发  │  │ 状态监控  │  │ 异常检测  │  │ 资源管理 │ │   │
│  │  └───────────┘  └───────────┘  └───────────┘  └──────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      Agent执行层                             │   │
│  │  ┌──────────────────────────────────────────────────────┐  │   │
│  │  │              AutonomousAgent（完全自主）               │  │   │
│  │  │  ┌─────────────────────────────────────────────────┐ │  │   │
│  │  │  │ AgenticLoop: 思考 → 选工具 → 执行 → 反思 → 继续  │ │  │   │
│  │  │  └─────────────────────────────────────────────────┘ │  │   │
│  │  └──────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    能力层（三层）                            │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐ │   │
│  │  │ L0: Foundation│  │ L1: Tools     │  │ L2: Skills      │ │   │
│  │  │ Read/Write    │  │ nmap/sqlmap   │  │ 领域知识包      │ │   │
│  │  │ Edit/Bash     │  │ fscan/...     │  │ 工作流模板      │ │   │
│  │  │ Glob/Grep     │  │               │  │                 │ │   │
│  │  └───────────────┘  └───────────────┘  └─────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    状态与通信层                              │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐ │   │
│  │  │ SelectorStore │  │ Memory System │  │ Prompt Cache    │ │   │
│  │  │ (状态订阅)    │  │ (Agent通信)   │  │ (Token优化)     │ │   │
│  │  └───────────────┘  └───────────────┘  └─────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      执行环境层                              │   │
│  │  ┌───────────────┐              ┌───────────────────────┐   │   │
│  │  │ 裸机运行环境  │              │  Docker工具容器       │   │   │
│  │  │ - Agent核心   │  ──调用──→   │  - nmap, nuclei      │   │   │
│  │  │ - 状态管理    │              │  - sqlmap, fscan     │   │   │
│  │  │ - HTTP工具    │              │  - 其他扫描工具      │   │   │
│  │  └───────────────┘              └───────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 核心数据流

```
输入目标 → Coordinator创建任务
              ↓
         AutonomousAgent启动
              ↓
         加载相关Skills
              ↓
         ┌─────────────────────┐
         │   AgenticLoop       │
         │                     │
         │  思考当前状态       │
         │      ↓              │
         │  选择工具/技能      │
         │      ↓              │
         │  构造参数           │
         │      ↓              │
         │  执行工具           │
         │      ↓              │
         │  处理结果           │
         │      ↓              │
         │  更新Memory/State   │
         │      ↓              │
         │  反思是否继续       │
         │      ↓              │
         │  [继续/完成]        │
         └─────────────────────┘
              ↓
         Flag / 失败报告
```

---

## 三、能力层设计

### 3.1 L0: 基础能力（Foundation）

**定义**: 所有Agent默认具备的基础能力，类似Claude Code的Read/Write/Edit/Bash。

```python
class FoundationTool(Enum):
    READ = "Read"          # 读取文件/URL/输出
    WRITE = "Write"        # 创建文件
    EDIT = "Edit"          # 编辑文件
    BASH = "Bash"          # 执行命令
    GLOB = "Glob"          # 文件搜索
    GREP = "Grep"          # 内容搜索
```

**特点**:
- 无需注册，默认可用
- Schema驱动，LLM自动构造调用
- 支持本地文件和远程URL

### 3.2 L1: 专业工具（Tools）

**定义**: 通过buildTool注册的专业安全工具。

**迁移优先级**:

| 优先级 | 工具 | 说明 |
|--------|------|------|
| P0 | nmap, nuclei, httpx, fscan | 扫描核心 |
| P0 | sqlmap | 注入利用 |
| P1 | ffuf, dirsearch | 目录枚举 |
| P1 | mimikatz, crackmapexec, impacket | 内网渗透 |
| P1 | msf, bloodhound | 利用框架 |

**工具Schema示例**:
```python
NMAP_TOOL = buildTool(
    name="nmap",
    description="端口扫描工具",
    parameters=[
        {"name": "target", "type": "string", "required": True},
        {"name": "ports", "type": "string", "default": "1-1000"},
        {"name": "scan_type", "type": "string", "enum": ["quick", "full", "service"]}
    ],
    handler=nmap_handler,
    permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK]
)
```

### 3.3 L2: 技能系统（Skills）

**定义**: 领域知识包，提供专业知识、工作流模板、工具推荐。

**核心技能**:
- `web_exploitation` - Web渗透技能
- `internal_network` - 内网渗透技能
- `ad_attack` - 域渗透技能
- `cloud_attack` - 云安全技能

**Skill结构**:
```yaml
name: web_exploitation
description: Web应用渗透技能
domain: web

knowledge: |
  ## Web渗透方法论
  ...

workflows:
  - name: sql_injection_workflow
    steps:
      - description: 识别注入点
        suggested_tools: ["sqlmap"]
      - description: 获取数据
        suggested_tools: ["sqlmap"]

tool_preferences:
  sqlmap: 0.9
  nmap: 0.8

examples:
  - scenario: SQL注入
    solution: 使用sqlmap自动利用
```

---

## 四、自主Agent设计

### 4.1 AgenticLoop

**核心循环**:
```
思考 → 选择工具 → 构造参数 → 执行 → 反思 → 继续/结束
```

**关键机制**:

1. **思考（Think）**
   - 分析当前状态
   - 评估距离目标的差距
   - 参考Skill知识
   - 决定下一步行动

2. **工具选择（Select Tool）**
   - 基于工具Schema自动选择
   - 考虑Skill的工具偏好
   - 检查权限约束

3. **执行（Execute）**
   - 调用Foundation或专业工具
   - 处理执行结果
   - 更新Memory

4. **反思（Reflect）**
   - 分析执行结果
   - 判断是否需要调整策略
   - 决定是否继续

### 4.2 终止条件

```python
def _should_stop(self) -> bool:
    if self.phase in [AgentPhase.COMPLETED, AgentPhase.FAILED]:
        return True
    if self.current_iteration >= self.max_iterations:
        return True
    if self.tokens_used >= self.max_tokens:
        return True
    if self._flag_found:
        return True
    return False
```

---

## 五、执行计划

### 5.1 模块迭代顺序

```
Phase 2.1: 基础能力层 (Day 1, 4小时)
    ↓
Phase 2.2: Skill系统 (Day 1-2, 4小时)
    ↓
Phase 2.3: 工具迁移 (Day 2-4, 12小时)
    ↓
Phase 2.4: 自主Agent (Day 4-5, 6小时)
    ↓
Phase 2.5: Coordinator集成 (Day 5-6, 6小时)
    ↓
Phase 2.6: 集成测试 (Day 6, 4小时)
```

### 5.2 详细任务

#### Phase 2.1: 基础能力层

**任务清单**:
- [ ] 创建 `app/capabilities/` 目录
- [ ] 实现 `foundation.py`
- [ ] 编写单元测试
- [ ] 验证基础能力可用

**验证标准**:
```python
foundation = FoundationCapability(workspace="/tmp/test")
result = await foundation.execute(FoundationTool.WRITE, {
    "file_path": "test.txt",
    "content": "Hello World"
})
assert result["success"] == True
```

#### Phase 2.2: Skill系统

**任务清单**:
- [ ] 创建 `app/skills/` 目录
- [ ] 实现 `base.py`
- [ ] 创建技能目录 `skills/`
- [ ] 编写核心技能YAML
- [ ] 编写技能加载器

**验证标准**:
```python
registry = SkillRegistry()
registry.load_from_directory("skills/")
skills = registry.find_matching_skills({"task": "SQL注入"})
assert len(skills) > 0
```

#### Phase 2.3: 工具迁移

**第一批 (Day 2)**: nmap, nuclei, httpx, fscan
**第二批 (Day 3)**: sqlmap, ffuf, dirsearch
**第三批 (Day 4)**: mimikatz, crackmapexec, impacket, msf, bloodhound

**验证标准**:
```python
registry = get_tool_registry_v2()
nmap = registry.get_tool("nmap")
result = await nmap.execute(
    params={"target": "127.0.0.1"},
    context={},
    agent_type="explore"
)
assert result.success == True
```

#### Phase 2.4: 自主Agent

**任务清单**:
- [ ] 创建 `app/agents/autonomous_agent.py`
- [ ] 实现AgenticLoop
- [ ] 集成Skill选择
- [ ] 集成Memory更新
- [ ] 编写测试

**验证标准**:
```python
agent = AutonomousAgent(...)
result = await agent.run(objective="扫描目标 http://example.com")
assert result["success"] == True
```

#### Phase 2.5: Coordinator集成

**任务清单**:
- [ ] 更新 `app/coordinator/dispatcher.py`
- [ ] 实现状态监控
- [ ] 实现异常检测
- [ ] 集成Prompt Cache

#### Phase 2.6: 集成测试

**测试场景**:
1. Web CTF: DVWA → 扫描 → 发现漏洞 → 利用 → Flag
2. 内网渗透: 靶场 → 探测 → 凭据 → 横向

---

## 六、风险控制

### 6.1 技术风险

| 风险 | 应对措施 |
|------|----------|
| LLM调用不稳定 | 重试机制 + 降级策略 |
| 工具执行超时 | 合理超时 + 后台执行 |
| Memory冲突 | 锁机制 |
| 无限循环 | 最大迭代次数限制 |

### 6.2 回滚策略

```bash
# 每个阶段打tag
git tag -a v2.0-phase2.1 -m "Phase 2.1 完成"

# 回滚
git checkout v2.0-phase2.X
```

---

## 七、时间估算

| 阶段 | 预计时间 |
|------|----------|
| Phase 2.1 基础能力 | 4小时 |
| Phase 2.2 Skill系统 | 4小时 |
| Phase 2.3 工具迁移 | 12小时 |
| Phase 2.4 自主Agent | 6小时 |
| Phase 2.5 Coordinator | 6小时 |
| Phase 2.6 集成测试 | 4小时 |
| **总计** | **约36小时（6天）** |

---

## 八、验收标准

### 8.1 功能验收

- [ ] Agent能自主扫描目标
- [ ] Agent能发现漏洞
- [ ] Agent能利用漏洞获取Flag
- [ ] Memory正确记录发现
- [ ] Skill正确加载和使用
- [ ] Coordinator正常监控

### 8.2 性能验收

- [ ] Prompt Cache节省Token > 50%
- [ ] 单次扫描响应时间 < 5分钟
- [ ] 系统稳定运行无崩溃

### 8.3 场景验收

- [ ] Web CTF场景可用
- [ ] 内网渗透场景可用
- [ ] 多目标并行扫描可用

---

## 九、与已完成模块的集成

### 9.1 Phase 1已完成的模块

Phase 1已经实现了核心基础设施：

| 模块 | 文件位置 | 状态 | 集成方式 |
|------|----------|------|----------|
| Agent类型系统 | `app/agents/base.py` | ✅ 已完成 | AutonomousAgent继承AgentType |
| Memory系统 | `app/memory/agent_memory.py` | ✅ 已完成 | 直接使用AgentMemorySystem |
| Prompt Cache | `app/memory/prompt_cache.py` | ✅ 已完成 | Coordinator使用ForkSubagentManager |
| SelectorStore | `app/state/selector_store.py` | ✅ 已完成 | AutonomousAgent订阅状态 |
| State V3 | `app/state/state_v3.py` | ✅ 已完成 | 作为全局状态定义 |
| ToolRegistryV2 | `app/tools_v2/tool_factory.py` | ✅ 已完成 | 工具迁移的目标注册表 |
| Coordinator | `app/coordinator/dispatcher.py` | ✅ 已完成 | 扩展监督功能 |

### 9.2 新旧模块关系

```
新模块（Phase 2新增）          已完成模块（Phase 1）
─────────────────────────────────────────────────────
capabilities/foundation.py     → 独立新增，不依赖旧模块

skills/base.py                 → 独立新增，使用tools_v2

agents/autonomous_agent.py     → 依赖已完成的：
                                - app/agents/base.py (AgentType)
                                - app/memory/agent_memory.py
                                - app/state/selector_store.py
                                - app/tools_v2/tool_factory.py

tools_v2/tools/*.py            → 使用已完成的：
                                - app/tools_v2/tool_factory.py (buildTool)
```

### 9.3 集成代码示例

```python
# app/agents/autonomous_agent.py 集成已完成的模块

from app.agents.base import AgentType, AGENT_REGISTRY
from app.memory.agent_memory import AgentMemorySystem, get_memory_system
from app.memory.prompt_cache import PromptCacheManager, ForkSubagentManager
from app.state.selector_store import SelectorStore, get_selector_store
from app.state.state_v3 import CTFStateV3, create_initial_state
from app.tools_v2.tool_factory import ToolRegistryV2, get_tool_registry_v2
from app.capabilities.foundation import FoundationCapability

class AutonomousAgent:
    def __init__(self, agent_type: AgentType, ...):
        # 使用已完成的Memory系统
        self.memory = get_memory_system()
        
        # 使用已完成的SelectorStore
        self.state_store = get_selector_store()
        
        # 使用已完成的ToolRegistryV2
        self.tool_registry = get_tool_registry_v2()
        
        # Phase 2新增：基础能力
        self.foundation = FoundationCapability(workspace=workspace)
        
        # Phase 2新增：Skill系统
        self.skill_registry = SkillRegistry()
```

---

## 附录

### A. 文件清单

```
app/
├── capabilities/           # Phase 2.1 新增
│   ├── __init__.py
│   └── foundation.py
├── skills/                 # Phase 2.2 新增
│   ├── __init__.py
│   └── base.py
├── tools_v2/               # Phase 1 完成，Phase 2.3 扩展
│   ├── __init__.py         ✅
│   ├── tool_factory.py     ✅
│   └── tools/              # Phase 2.3 迁移
│       ├── nmap.py
│       ├── nuclei.py
│       └── ...
├── agents/
│   ├── __init__.py         ✅
│   ├── base.py             ✅ Phase 1 完成
│   └── autonomous_agent.py # Phase 2.4 新增
├── memory/                 ✅ Phase 1 完成
│   ├── __init__.py
│   ├── agent_memory.py
│   └── prompt_cache.py
├── state/                  ✅ Phase 1 完成
│   ├── __init__.py
│   ├── state_v3.py
│   └── selector_store.py
├── coordinator/            ✅ Phase 1 完成，Phase 2.5 扩展
│   ├── __init__.py
│   └── dispatcher.py
└── compressor/             ✅ Phase 1 完成
    ├── __init__.py
    └── smart_compressor.py

skills/                     # Phase 2.2 新增（项目根目录）
├── web_exploitation.yaml
├── internal_network.yaml
├── ad_attack.yaml
└── cloud_attack.yaml
```

### B. 参考文档

- Claude Code技术文档
- Agent系统深度技术文档
- 工具系统深度技术文档
- MCP与扩展系统技术文档