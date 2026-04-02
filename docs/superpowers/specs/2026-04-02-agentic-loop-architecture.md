# CTF-Agent 2.0 AgenticLoop架构设计

> **设计目标**: 实现Claude Code风格的自主驱动全流程智能渗透架构
> **设计原则**: 简洁高效、深度复用、动态调度、自我纠错
> **创建日期**: 2026-04-02

---

## 核心特性

1. **AgenticLoop驱动**: Think→Act→Reflect动态循环，无固定流程
2. **智能决策**: Agent自主选择工具/派发子Agent/切换阶段
3. **深度集成**: 完全复用现有工具延迟加载、Memory、Skill系统
4. **子Agent嵌套**: 支持无限层级Fork派发
5. **超时熔断**: 唯一停止条件，防止无限运行

---

## 架构对比

| 传统固定流程 | AgenticLoop架构 |
|-------------|-----------------|
| Explore→Plan→Attack→Verify | Think→Act→Reflect→Decide |
| 节点预定义跳转 | Agent自主决策下一步 |
| 流程硬编码 | 工具选择包括工具/子Agent/阶段切换 |
| 状态机驱动 | AgenticLoop驱动 |

---

## 核心架构图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              用户层                                          │
│                    python -m app.main http://target.com                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            入口层 (main.py)                                  │
│                                                                             │
│  职责:                                                                       │
│  - CLI参数解析                                                               │
│  - 智能分类挑战类型 (LLM)                                                    │
│  - 创建初始状态 + 启动超时                                                    │
│  - 调用Graph执行                                                             │
│  - 结果格式化输出                                                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         主图层 (ctf_graph.py)                                │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         AgenticLoop                                 │   │
│  │                                                                     │   │
│  │     ┌─────────────┐      ┌─────────────┐      ┌─────────────┐     │   │
│  │     │   Think     │ ───► │     Act     │ ───► │   Reflect   │     │   │
│  │     │             │      │             │      │             │     │   │
│  │     │ LLM决策     │      │ 执行行动    │      │ 学习反思    │     │   │
│  │     │ 分析状态    │      │ 工具/子Agent│      │ 更新Memory  │     │   │
│  │     │ 选择行动    │      │ 阶段切换    │      │ 提取发现    │     │   │
│  │     └─────────────┘      └─────────────┘      └─────────────┘     │   │
│  │            │                    │                    │            │   │
│  │            │                    ▼                    │            │   │
│  │            │         ┌─────────────────┐            │            │   │
│  │            │         │ 决策路由        │            │            │   │
│  │            │         │ Continue/End    │            │            │   │
│  │            │         └────────┬────────┘            │            │   │
│  │            │                  │                      │            │   │
│  │            └──────────────────┘                      │            │   │
│  │                       ▲                              │            │   │
│  │                       └──────────────────────────────┘            │   │
│  │                                                                     │   │
│  │  结束条件:                                                           │   │
│  │  1. 找到Flag                                                        │   │
│  │  2. 超时 (唯一硬性停止)                                              │   │
│  │  3. 达到最大迭代                                                     │   │
│  │  4. Agent决策完成                                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  编译: MemorySaver持久化                                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         集成层 (现有组件复用)                                │
│                                                                             │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐  │
│  │deferred_loader│ │skill_registry │ │ agent_memory  │ │   llm_client  │  │
│  │               │ │               │ │               │ │               │  │
│  │ 延迟加载工具  │ │ Skill推荐     │ │ Memory读写    │ │ LLM调用       │  │
│  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘  │
│                                                                             │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐  │
│  │  tools_v2     │ │docker_executor│ │  dispatcher   │ │concurrency_cfg│  │
│  │               │ │               │ │               │ │               │  │
│  │ 工具执行      │ │ Docker容器    │ │ 子Agent派发   │ │ 并发安全      │  │
│  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘  │
│                                                                             │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐                    │
│  │flag_extractor │ │context_compr  │ │ prompt_cache  │                    │
│  │               │ │               │ │               │                    │
│  │ Flag提取      │ │ 上下文压缩    │ │ Token优化     │                    │
│  └───────────────┘ └───────────────┘ └───────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 行动类型定义

```python
class ActionType(Enum):
    """Agent可选择的行动类型"""
    
    # 1. 直接工具调用
    DIRECT_TOOL = "direct_tool"
    # 示例: {"type": "direct_tool", "tool": "nmap", "params": {"target": "..."}}
    
    # 2. 派发子Agent
    DISPATCH_SUBAGENT = "dispatch_subagent"
    # 示例: {"type": "dispatch_subagent", "agent_type": "explore", "targets": [...]}
    
    # 3. 阶段切换
    SWITCH_PHASE = "switch_phase"
    # 示例: {"type": "switch_phase", "new_phase": "attack"}
    
    # 4. 任务完成
    COMPLETE = "complete"
    # 示例: {"type": "complete", "reason": "flag_found"}
```

---

## 节点职责详解

### Think节点

**职责**: 分析当前状态，LLM决策下一步行动

**集成组件**:
- `deferred_loader.get_tools_for_context()` - 获取当前应加载的工具
- `skill_registry.find_matching_skills()` - 获取Skill推荐
- `agent_memory.read_findings()` - 读取历史发现
- `llm_client.ainvoke()` - LLM决策调用

**输入**: 当前状态（阶段、发现、迭代次数）

**输出**: `next_action` - 行动决策

**核心逻辑**:
```python
async def think_node(state: CTFStateV3) -> CTFStateV3:
    # 1. 检查超时（唯一停止条件）
    if dispatcher.should_stop(session_id):
        return complete_action
    
    # 2. 获取延迟加载工具
    available_tools = deferred_registry.get_tools_for_context(context)
    
    # 3. 获取Skill推荐
    skill_suggestions = skill_registry.find_matching_skills(context)
    
    # 4. 读取Memory
    relevant_memories = memory.read_findings(target, topics)
    
    # 5. 构建决策Prompt
    prompt = build_decision_prompt(state, tools, skills, memories)
    
    # 6. LLM决策
    response = await llm.ainvoke(prompt)
    
    # 7. 解析决策
    state["next_action"] = parse_action_response(response)
    
    return state
```

### Act节点

**职责**: 执行Think决策的行动

**集成组件**:
- `tools_v2.tools.execute_tool()` - 工具执行
- `docker_executor` - Docker容器执行（内部已集成）
- `dispatcher.dispatch_parallel_agents()` - 子Agent派发
- `concurrency_config.get_max_concurrent()` - 并发控制

**输入**: `next_action`

**输出**: `last_tool_result` / `last_subagent_result`

**核心逻辑**:
```python
async def act_node(state: CTFStateV3) -> CTFStateV3:
    action = state["next_action"]
    
    if action["type"] == ActionType.DIRECT_TOOL:
        # 直接调用工具（内部已支持Docker）
        result = await execute_tool(action["tool"], action["params"])
        state["last_tool_result"] = result
    
    elif action["type"] == ActionType.DISPATCH_SUBAGENT:
        # 派发子Agent（并行执行）
        result = await dispatcher.dispatch_parallel_agents(...)
        result = await dispatcher.execute_all_fork_tasks(...)
        state["last_subagent_result"] = result
    
    elif action["type"] == ActionType.SWITCH_PHASE:
        # 阶段切换
        state["current_phase"] = action["new_phase"]
    
    elif action["type"] == ActionType.COMPLETE:
        # 任务完成
        state["current_phase"] = PhaseType.COMPLETE
    
    state["iteration_count"] += 1
    return state
```

### Reflect节点

**职责**: 分析结果，学习反思，更新知识库

**集成组件**:
- `agent_memory.write_finding()` - 写入Memory
- `flag_extractor_v2.extract_flags()` - Flag提取
- `context_compressor.compress_context()` - 上下文压缩

**输入**: `last_tool_result` / `last_subagent_result`

**输出**: 更新 `findings`, `flags_found`

**核心逻辑**:
```python
async def reflect_node(state: CTFStateV3) -> CTFStateV3:
    # 1. 分析工具结果
    if tool_result := state.get("last_tool_result"):
        findings = extract_findings_from_result(tool_result)
        state["findings"].extend(findings)
        
        # 写入Memory
        for finding in findings:
            await memory.write_finding(agent_type, target, topic, finding)
        
        # Flag提取
        flags = extract_flags(str(tool_result))
        state["flags_found"].extend(flags)
    
    # 2. 分析子Agent结果
    if subagent_result := state.get("last_subagent_result"):
        state["findings"].extend(subagent_result.get("findings", []))
    
    # 3. 上下文压缩
    if len(state["findings"]) > 20:
        state["findings"] = compress_context(state["findings"])
    
    return state
```

---

## 与Claude Code的对应关系

| Claude Code机制 | 本设计实现 |
|----------------|-----------|
| AgenticLoop: Think→Act→Reflect | 完全一致的三节点循环 |
| Agent工具派发 | Act节点: `DISPATCH_SUBAGENT` 行动类型 |
| Fork子Agent | `CoordinatorDispatcher.dispatch_parallel_agents()` |
| Prompt Cache共享 | `ForkSubagentManager.build_forked_messages()` |
| 延迟加载工具 | `deferred_loader.get_tools_for_context()` |
| 并发安全控制 | `concurrency_config.get_max_concurrent()` |
| 超时熔断 | `CoordinatorDispatcher.should_stop()` |
| Memory系统 | `agent_memory.read/write_finding()` |
| 上下文压缩 | `context_compressor.compress_context()` |

---

## 关键设计决策

### 决策1: 为什么选择AgenticLoop而非固定流程？

| 对比项 | 固定流程 | AgenticLoop |
|--------|---------|-------------|
| 灵活性 | 低，无法跳过阶段 | 高，Agent自主决策 |
| 自主性 | 低，预定义路径 | 高，LLM选择行动 |
| 复杂度 | 低，流程简单 | 中，需要LLM决策 |
| 适用性 | 仅适合标准CTF | 适合任意渗透场景 |
| Claude Code模式 | ❌ 不符合 | ✅ 完全符合 |

### 决策2: 为什么Think节点使用LLM决策？

- **Claude Code模式**: Claude Code的核心是LLM驱动的思考过程
- **动态适应**: 不同场景需要不同策略，规则无法覆盖
- **智能权衡**: LLM可以在工具选择、派发子Agent、阶段切换间智能决策

### 决策3: 为什么超时是唯一硬性停止条件？

- **Claude Code模式**: Claude Code也使用超时熔断
- **防止无限循环**: Agent可能陷入死循环
- **资源控制**: 渗透测试有时间限制

---

## 文件清单与代码量

### 新增文件

```
app/
├── main.py                           # ~150行：统一入口
└── graph/
    ├── __init__.py                   # ~10行：模块导出
    ├── ctf_graph.py                  # ~100行：主图构建
    └── nodes.py                      # ~300行：节点实现

总计: ~560行新增代码
```

### 修改文件

```
config.yaml                           # +5行：graph配置节
```

### 文件职责

| 文件 | 职责 | 核心函数 |
|------|------|---------|
| `app/main.py` | 统一入口 | `run_agent()`, `main()` |
| `app/graph/__init__.py` | 模块导出 | - |
| `app/graph/ctf_graph.py` | 主图构建 | `build_ctf_graph()`, `decide_next()` |
| `app/graph/nodes.py` | 节点实现 | `think_node()`, `act_node()`, `reflect_node()` |

---

## 实现步骤

```
Step 1: 创建app/graph/nodes.py
        - 实现think_node()
        - 实现act_node()
        - 实现reflect_node()
        - 实现辅助函数

Step 2: 创建app/graph/ctf_graph.py
        - 定义ActionType枚举
        - 实现build_ctf_graph()
        - 实现decide_next()路由

Step 3: 创建app/main.py
        - 实现run_agent()
        - 实现CLI入口
        - 实现结果格式化

Step 4: 更新config.yaml
        - 添加graph配置节

Step 5: 集成测试
        - 测试基本执行流程
        - 测试子Agent派发
        - 测试超时熔断
```

---

## 子Agent派发流程

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   Act节点: dispatch_subagent 行动                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              CoordinatorDispatcher.dispatch_parallel_agents()               │
│                                                                             │
│  1. 创建ForkTask任务列表                                                    │
│  2. 构建Fork消息（带Prompt Cache）                                          │
│  3. 设置并发限制                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  CoordinatorDispatcher.execute_all_fork_tasks()             │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│  │  SubAgent #1    │  │  SubAgent #2    │  │  SubAgent #3    │            │
│  │                 │  │                 │  │                 │            │
│  │  Think → Act    │  │  Think → Act    │  │  Think → Act    │            │
│  │    ↓      ↓     │  │    ↓      ↓     │  │    ↓      ↓     │            │
│  │  Reflect ───    │  │  Reflect ───    │  │  Reflect ───    │            │
│  │    ↓            │  │    ↓            │  │    ↓            │            │
│  │  [findings]     │  │  [findings]     │  │  [findings]     │            │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘            │
│           │                    │                    │                      │
│           └────────────────────┼────────────────────┘                      │
│                                │                                           │
│                                ▼                                           │
│                    aggregate_results()                                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    返回聚合结果到父Agent
```

---

## 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| LLM决策不稳定 | 行动选择错误 | Prompt优化 + 多轮验证 |
| Token消耗过大 | 成本高 | Prompt Cache + 上下文压缩 |
| 子Agent无限嵌套 | 资源耗尽 | 最大深度限制(3层) |
| 超时设置不合理 | 任务中断 | 智能分类任务类型自动设置 |

---

## 性能预期

| 指标 | 预期值 | 说明 |
|------|-------|------|
| 单次迭代耗时 | 3-10秒 | 取决于工具执行 |
| 平均完成迭代数 | 15-30次 | 根据任务复杂度 |
| 子Agent派发延迟 | <1秒 | CoordinatorDispatcher已优化 |
| Memory写入延迟 | <100ms | 异步写入 |
| Token节省率 | ~40% | Prompt Cache + 压缩 |

---

## 配置说明

```yaml
# config.yaml 新增配置项

graph:
  max_iterations: 50           # 最大迭代次数
  checkpoint_enabled: true     # 状态持久化
  
subagent:
  max_depth: 3                 # 子Agent最大嵌套深度
  default_max_iterations: 10   # 子Agent默认迭代次数
```

---

## 使用示例

### CLI使用

```bash
# 基本使用
python -m app.main http://target.com

# 指定类型
python -m app.main 192.168.1.100 -t network

# 指定超时
python -m app.main http://target.com --timeout 60

# 详细输出
python -m app.main http://target.com -v
```

### 代码调用

```python
from app.main import run_agent

result = await run_agent(
    target="http://target.com",
    description="SQL注入测试",
    max_iterations=30,
    timeout_minutes=60
)

print(f"成功: {result['success']}")
print(f"Flags: {result['flags']}")
```

---

## 设计验证清单

- [x] 符合Claude Code AgenticLoop模式
- [x] 深度集成现有系统（零重复代码）
- [x] 支持动态调度（无固定流程）
- [x] 支持子Agent派发（Fork机制）
- [x] 超时熔断（唯一硬性停止）
- [x] 自我纠错（Reflect学习）
- [x] 简洁高效（~560行新增代码）
- [x] 配置驱动（易于调整）

---

## 下一步行动

1. **用户审批设计文档** - 确认设计方案
2. **使用writing-plans skill** - 创建详细实现计划
3. **实现代码** - 按步骤实现
4. **集成测试** - 验证完整流程

---

**设计完成日期**: 2026-04-02
**设计者**: Claude Code (Haiku 4.5)