# AI Agent 框架调研报告

**调研日期**: 2026-04-07
**调研目标**: 为 CTF-Agent 2.0 架构升级提供参考

---

## 1. LangGraph (langchain-ai/langgraph)

**Stars**: 28,567
**定位**: Low-level orchestration framework for stateful agents

### 1.1 核心架构模式

```python
# LangGraph 核心执行循环 (Pregel 算法)
class Pregel:
    """
    基于 Pregel (Google Pregel paper) 和 Apache Beam 的图执行引擎
    - 节点并行执行
    - 状态通过 Channels 管理
    - Checkpointer 持久化
    """

# 核心执行伪代码
while tasks_not_empty:
    # 1. Prepare next tasks (并行)
    tasks = prepare_next_tasks(checkpoint, channels)

    # 2. Execute tasks (并行)
    results = execute_parallel(tasks)

    # 3. Apply writes to channels
    apply_writes(results, channels)

    # 4. Check interrupts
    if has_interrupts():
        checkpoint = save_checkpoint()
        return interrupted_state  # 可恢复

    # 5. Commit checkpoint (持久化)
    checkpoint = commit_checkpoint()

# StateGraph 定义
graph = StateGraph(StateSchema)
graph.add_node("node_a", node_function)
graph.add_edge("node_a", "node_b")
graph.compile(checkpointer=MemorySaver())
```

### 1.2 关键创新点

| 特性 | 说明 |
|------|------|
| **StateGraph** | 基于状态机的图结构，节点间通过状态传递数据 |
| **Channels** | 状态通道系统，支持 LastValue/Topic/BinOp 等多种合并策略 |
| **Checkpointer** | 持久化系统，支持 SQLite/Postgres/Redis/Memory |
| **interrupt()** | Human-in-the-loop 机制，暂停并返回值给客户端 |
| **Command** | 恢复机制，支持 `update`, `resume`, `goto` |
| **Durable Execution** | 失败自动恢复，从 checkpoint 继续 |
| **Durability Modes** | `sync`/`async`/`exit` 三种持久化模式 |

### 1.3 interrupt() + Command 机制详解

```python
# interrupt - 暂停并等待人类输入
def human_approval_node(state):
    approval = interrupt({
        "question": "Approve this action?",
        "context": state["pending_action"]
    })
    # approval 是恢复时 Command 提供的值
    if approval:
        return {"approved": True}

# Command - 恢复执行
# 客户端恢复时：
Command(resume={"approval_id": "yes"})  # 提供恢复值
Command(goto="next_node")  # 跳转到指定节点
Command(update={"approved": True})  # 更新状态
Command(graph=Command.PARENT)  # 控制父图
```

### 1.4 可借鉴设计

- **Checkpointer 持久化**: CTF-Agent 可用于保存攻击进度，支持暂停/恢复
- **interrupt() Human-in-the-loop**: 允许人类审核高风险操作（如提交 FLAG）
- **Command 恢复机制**: 支持 `resume` + `goto` 组合
- **Durability Modes**: `sync` 立即持久化、`async` 后台持久化、`exit` 仅退出时

### 1.5 符合"框架只做管道"程度

**评分: ⭐⭐⭐⭐ (4/5)**

- LangGraph 是低级框架，核心是图执行引擎
- AI 决定节点逻辑和流转，框架只管理状态和执行
- Checkpointer/interrupt 是基础设施，不干预 AI 决策
- 但 StateGraph 的定义方式增加了复杂性

---

## 2. AutoGPT (Significant-Gravitas/AutoGPT)

**Stars**: 183,193
**定位**: Platform for continuous AI agents

### 2.1 核心架构模式

```
AutoGPT Platform 架构 (新版):

┌─────────────────────────────────────────────┐
│                 Frontend                     │
│  ┌───────────┐  ┌───────────┐  ┌─────────┐  │
│  │Agent Builder│ │ Workflow │  │ Dashboard│ │
│  │  (Low-code) │ │Management│  │(Monitor)│ │
│  └───────────┘  └───────────┘  └─────────┘  │
└─────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────┐
│                 Server                       │
│  ┌───────────┐  ┌───────────┐  ┌─────────┐  │
│  │  Blocks   │  │  Agent   │  │  Memory │  │
│  │(Components)│ │ Runtime  │  │  Store  │  │
│  └───────────┘  └───────────┘  └─────────┘  │
│                                              │
│  Block = 单一功能的可组合单元                │
│  Agent = Blocks 的组合编排                   │
└─────────────────────────────────────────────┘

# Block 设计模式
class Block:
    name: str
    inputs: dict  # 输入参数
    outputs: dict  # 输出参数
    execute(inputs) -> outputs  # 执行逻辑

# Agent 工作流
workflow = connect_blocks([
    WebScraperBlock(url=input_url),
    TextProcessorBlock(text=scraper_output),
    LLMBlock(prompt=processed_text),
    EmailSenderBlock(content=llm_output)
])
```

### 2.2 关键创新点

| 特性 | 说明 |
|------|------|
| **Block System** | 可组合的功能单元，类似 LEGO |
| **Visual Workflow Builder** | 低代码可视化构建 |
| **Agent Runtime** | 长运行 Agent 的执行引擎 |
| **Memory Store** | 持久化记忆系统 |
| **Trigger System** | 外部事件触发 Agent |
| **Deployment** | Docker + Cloud 部署支持 |

### 2.3 可借鉴设计

- **Block 组合模式**: CTF-Agent 的 Skill 系统可借鉴 Block 设计
- **触发器系统**: 支持外部事件触发攻击（如新题目发布）
- **可视化 Dashboard**: 监控攻击进度和结果

### 2.4 符合"框架只做管道"程度

**评分: ⭐⭐⭐ (3/5)**

- AutoGPT 是完整平台，框架干预较多
- Block 设计限制了 AI 的自主性
- 更适合业务流程自动化，而非自主攻击

---

## 3. BabyAGI (yoheinakajima/babyagi)

**Stars**: 22,215
**定位**: Self-building autonomous agent framework

### 3.1 核心架构模式

```python
# BabyAGI 新版架构 (functionz 框架)
@babyagi.register_function(
    dependencies=["function_a"],
    key_dependencies=["openai_api_key"],
    metadata={"description": "功能描述"}
)
def my_function(arg1, arg2):
    result = function_a(arg1)  # 自动加载依赖
    return process(result, arg2)

# 核心概念
# 1. 函数注册 - 带元数据的函数
# 2. 依赖追踪 - 图结构追踪依赖关系
# 3. 自动加载 - 执行时自动加载所需函数
# 4. 自我构建 - AI 可生成新函数并注册

# Self-Building 流程
def self_build(user_description, num_tasks):
    # 1. 生成 X 个典型任务
    tasks = generate_tasks(user_description, num_tasks)

    # 2. 对每个任务
    for task in tasks:
        # 3. 检查是否有现成函数
        if no_matching_function(task):
            # 4. AI 编写新函数
            new_function = ai_write_function(task)
            # 5. 注册新函数
            babyagi.register_function(new_function)
        # 6. 执行任务
        execute_task(task)
```

### 3.2 关键创新点

| 特性 | 说明 |
|------|------|
| **functionz 框架** | 函数数据库 + 依赖图 |
| **Self-Building** | AI 自动生成并注册新函数 |
| **Dashboard** | 函数管理可视化界面 |
| **Trigger System** | 函数间触发器 |
| **Key Management** | 安全存储 API keys |

### 3.3 可借鉴设计

- **Self-Building 理念**: AI 可动态创建新 Skills
- **函数依赖图**: 自动管理 Skill 间的依赖
- **Dashboard**: 监控函数调用和执行日志

### 3.4 符合"框架只做管道"程度

**评分: ⭐⭐⭐⭐⭐ (5/5)**

- BabyAGI 是最符合"框架只做管道"的设计
- 核心是函数管理基础设施，AI 决定一切
- Self-Building 让 AI 自主扩展能力
- 极简设计，无复杂编排逻辑

---

## 4. OpenAI Agents SDK (openai/openai-agents-js)

**Stars**: 2,594
**定位**: Lightweight framework for multi-agent workflows

### 4.1 核心架构模式

```typescript
// Agent 定义
const agent = new Agent({
    name: 'Assistant',
    instructions: 'You are a helpful assistant',
    tools: [tool1, tool2],
    handoffs: [agent2, agent3],  // 可交接给其他 Agent
    inputGuardrails: [guardrail1],
    outputGuardrails: [guardrail2],
});

// 执行循环
async function runLoop(agent, input) {
    state = new RunState(agent, input);

    while (!state.isDone) {
        // 1. 准备 turn
        turn = prepareTurn(state);

        // 2. 调用模型
        response = await model.chat(turn.input, tools);

        // 3. 处理响应
        processed = processModelResponse(response);

        // 4. 检查 handoffs
        if (processed.hasHandoff) {
            state.currentAgent = processed.handoffTarget;
            continue;  // 切换 Agent
        }

        // 5. 执行工具
        if (processed.hasToolCalls) {
            results = await executeTools(processed.toolCalls);
            state.generatedItems.push(results);
        }

        // 6. 检查 interruption (human-in-the-loop)
        if (processed.needsApproval) {
            return { type: 'interruption', pendingApprovals };
        }

        // 7. 更新状态
        state.currentStep = processed.nextStep;
    }

    return state.finalOutput;
}

// Handoff 机制
const handoffTool = handoff(agent2, {
    toolName: 'transfer_to_specialist',
    toolDescription: 'Hand off to specialist agent',
    inputFilter: (input) => filterSensitiveData(input)
});
```

### 4.2 关键创新点

| 特性 | 说明 |
|------|------|
| **Handoffs** | Agent 间交接，类似工具调用但切换 Agent |
| **Guardrails** | 输入/输出验证，安全边界 |
| **Sessions** | 自动管理对话历史 |
| **Tracing** | 内置执行追踪和可视化 |
| **Human-in-the-loop** | 工具审批机制 (ToolApproval) |
| **Realtime Agents** | 支持语音 Agent |

### 4.3 Handoff vs Tool 对比

```typescript
// Tool - 执行后返回结果，当前 Agent 继续
tool: {
    name: 'search_web',
    execute: async (query) => { return searchResults; }
}

// Handoff - 切换到目标 Agent，目标 Agent 接管
handoff: {
    name: 'transfer_to_specialist',
    targetAgent: specialistAgent,
    onHandoff: async (input) => {
        // 可过滤输入、设置上下文
        return filteredInput;
    }
}
```

### 4.4 可借鉴设计

- **Handoffs**: 支持多 Agent 协作（如侦察 Agent → 攻击 Agent → 提交 Agent）
- **Guardrails**: 输入验证防止注入，输出验证确保格式
- **Sessions**: 自动管理对话历史
- **Tool Approval**: 高风险操作需人工确认

### 4.5 符合"框架只做管道"程度

**评分: ⭐⭐⭐⭐⭐ (5/5)**

- 极简设计，核心是 Agent + Run + Tools
- AI 决定一切：选择工具、决定 Handoff、生成输出
- 框架只提供基础设施：Guardrails、Sessions、Tracing
- 完全符合"框架只做管道"理念

---

## 5. 综合对比表

| 特性 | LangGraph | AutoGPT | BabyAGI | OpenAI Agents SDK | CTF-Agent 2.0 |
|------|-----------|---------|---------|-------------------|---------------|
| **核心模式** | StateGraph + Pregel | Blocks + Workflow | Functions + Self-Build | Agent + Run Loop | Query Loop |
| **持久化** | Checkpointer | Memory Store | 函数数据库 | Sessions | 可选（可借鉴） |
| **Human-in-the-loop** | interrupt() | 触发器 | Dashboard | ToolApproval | 可借鉴 |
| **恢复机制** | Command | Workflow 状态 | 函数版本 | RunState | 无（可借鉴） |
| **多 Agent** | Subgraph | 多 Block 组合 | 函数依赖 | Handoffs | 可借鉴 |
| **框架干预程度** | 中 | 高 | 低 | 低 | 低 |
| **"管道"评分** | 4/5 | 3/5 | 5/5 | 5/5 | 4/5 |

---

## 6. CTF-Agent 2.0 可借鉴设计

### 6.1 高优先级借鉴

#### A. LangGraph Checkpointer + interrupt

```python
# 当前 CTF-Agent Query Loop
while not done:
    messages = manage_context_window(messages)
    response = llm.chat(messages, tools)
    if has_tool_calls(response):
        results = execute_tools(tool_calls)
        messages.append(results)
    else:
        done = True

# 建议增强
class CTFAgent:
    def __init__(self, checkpointer=None):
        self.checkpointer = checkpointer  # 新增：持久化

    def run(self, challenge_url):
        # 加载 checkpoint（如果有）
        checkpoint = self.checkpointer.load(challenge_url)

        while not done:
            # ... 现有逻辑 ...

            # 新增：interrupt 支持
            if needs_human_approval(tool_call):
                approval = interrupt({
                    "type": "approval",
                    "tool": tool_call.name,
                    "args": tool_call.args,
                    "reason": "高风险操作"
                })
                if not approval:
                    continue  # 拒绝，跳过此工具

            # 新增：保存 checkpoint
            self.checkpointer.save(challenge_url, {
                "messages": messages,
                "progress": current_progress,
                "tools_used": tools_used
            })

    def resume(self, challenge_url, command):
        """恢复执行"""
        checkpoint = self.checkpointer.load(challenge_url)
        if command.resume:
            # 使用 command 提供的值继续
            messages.append(command.resume)
        if command.goto:
            # 跳转到指定阶段
            current_phase = command.goto
        # 继续执行...
```

#### B. OpenAI Agents SDK Handoffs

```python
# 多 Agent 协作
agents = {
    "recon": ReconAgent(tools=[scan, nmap, dirsearch]),
    "attack": AttackAgent(tools=[exploit, shell, sqli]),
    "submit": SubmitAgent(tools=[submit_flag, check_score])
}

# Handoff 定义
recon_agent.add_handoff(attack_agent, {
    "condition": "found vulnerability",
    "transfer_input": lambda state: {
        "vulnerability": state["vulnerability"],
        "target": state["target"]
    }
})

attack_agent.add_handoff(submit_agent, {
    "condition": "found flag",
    "transfer_input": lambda state: {
        "flag": state["flag"],
        "challenge_id": state["challenge_id"]
    }
})

# 执行时
current_agent = recon_agent
while not done:
    result = current_agent.run(state)
    if result.has_handoff:
        current_agent = result.handoff_target
        state = result.transfer_input(state)
    # ...
```

### 6.2 中优先级借鉴

#### C. BabyAGI Self-Building

```python
# 动态 Skill 生成
def self_build_skill(attack_scenario):
    """AI 根据场景自动生成新 Skill"""
    # 检查是否有现成 Skill
    matching_skills = search_skills(attack_scenario)
    if matching_skills:
        return matching_skills[0]

    # AI 编写新 Skill
    new_skill = llm.generate_skill(attack_scenario)

    # 注册新 Skill
    skills.register(new_skill)

    return new_skill

# 示例：遇到新 OA 系统
skill = self_build_skill("泛微 OA RCE")
# AI 自动生成：ecology_rce.yaml
```

#### D. OpenAI Agents SDK Guardrails

```python
# 输入 Guardrail
def validate_target_url(input):
    """防止 SSRF 和非法目标"""
    url = input.get("url")
    if not is_valid_ctf_target(url):
        raise GuardrailError("非法目标 URL")
    return input

# 输出 Guardrail
def validate_flag_format(output):
    """确保 FLAG 格式正确"""
    flag = output.get("flag")
    if not matches_flag_pattern(flag):
        raise GuardrailError("FLAG 格式不正确")
    return output

agent.add_input_guardrail(validate_target_url)
agent.add_output_guardrail(validate_flag_format)
```

### 6.3 低优先级借鉴

#### E. LangGraph Durability Modes

```python
# 持久化模式选择
class CTFAgent:
    def run(self, challenge_url, durability="async"):
        """
        durability:
        - "sync": 每步立即持久化（安全但慢）
        - "async": 后台持久化（推荐）
        - "exit": 仅退出时持久化（最快但风险）
        """
        if durability == "sync":
            self.checkpointer.commit_every_step()
        elif durability == "async":
            self.checkpointer.commit_background()
        else:
            self.checkpointer.commit_on_exit()
```

#### F. AutoGPT Block System

```python
# Skill 作为 Block
class NmapBlock:
    inputs = {"target": str, "options": dict}
    outputs = {"ports": list, "services": dict}

    def execute(self, inputs):
        result = bash(f"nmap {inputs['target']} {inputs['options']}")
        return parse_nmap_output(result)

# 组合多个 Block
workflow = [
    NmapBlock(target=challenge_url),
    DirsearchBlock(target=nmap_output["http_port"]),
    SqliBlock(url=dirsearch_output["admin_path"])
]
```

---

## 7. 最终建议

### 7.1 立即可实施（低改动）

1. **添加 Checkpointer**: 使用 SQLite 或 Memory 持久化攻击进度
2. **添加 interrupt()**: 高风险操作（提交 FLAG）暂停等待确认
3. **添加 Command 恢复**: 支持 `resume` 从 checkpoint 继续

### 7.2 中期可考虑（中改动）

1. **添加 Handoffs**: 多 Agent 协作（侦察 → 攻击 → 提交）
2. **添加 Guardrails**: 输入/输出验证
3. **添加 Sessions**: 自动管理对话历史

### 7.3 长期探索（大改动）

1. **Self-Building Skills**: AI 动态生成新攻击技能
2. **可视化 Dashboard**: 监控攻击进度和结果
3. **完整 LangGraph 集成**: 使用 StateGraph 定义攻击流程

---

## 8. 结论

**最符合"框架只做管道"的框架**: BabyAGI 和 OpenAI Agents SDK

**对 CTF-Agent 最有价值的借鉴**:
1. LangGraph 的 **Checkpointer + interrupt + Command**（持久化 + Human-in-the-loop + 恢复）
2. OpenAI Agents SDK 的 **Handoffs + Guardrails**（多 Agent + 安全边界）

**实施优先级**:
- 立即：Checkpointer + interrupt（最实用）
- 中期：Handoffs + Guardrails（增强能力）
- 长期：Self-Building（自主进化）

---

**调研完成时间**: 2026-04-07
**调研工具**: GitHub API via gh CLI