# Claude Code Agent 系统深度技术文档

> 版本: 2.1.88
> 目的: 为开发者提供 Agent 系统的完整实现细节和学习参考

---

## 目录

1. [Agent 系统架构总览](#1-agent-系统架构总览)
2. [内置代理类型详解](#2-内置代理类型详解)
3. [Fork 子代理机制](#3-fork-子代理机制)
4. [协调者模式实现](#4-协调者模式实现)
5. [runAgent 核心执行引擎](#5-runagent-核心执行引擎)
6. [Agent 工具输入与参数](#6-agent-工具输入与参数)
7. [Agent 与 MCP 集成](#7-agent-与-mcp-集成)
8. [Agent 生命周期管理](#8-agent-生命周期管理)
9. [实际应用案例](#9-实际应用案例)
10. [设计模式与最佳实践](#10-设计模式与最佳实践)

---

## 1. Agent 系统架构总览

### 1.1 核心设计理念

Claude Code 的 Agent 系统采用了**分层委托架构**:

```
用户请求 → 主代理 (Main Agent) → 子代理 (Subagent) → 工具执行
                        ↓
                  协调者模式 (可选)
                        ↓
                  多工作代理并行
```

**关键设计原则:**

1. **上下文隔离**: 每个子代理有独立的对话上下文
2. **工具池继承**: 子代理可以继承或定制父代理的工具集
3. **并行执行**: 支持同时启动多个子代理处理独立任务
4. **结果汇总**: 子代理结果以 `<task-notification>` 格式返回主代理

### 1.2 核心文件结构

```
src/tools/AgentTool/
├── AgentTool.tsx          # Agent 工具主实现 (6000+ 行)
├── runAgent.ts            # 核心执行引擎
├── forkSubagent.ts        # Fork 机制实现
├── builtInAgents.ts       # 内置代理注册
├── loadAgentsDir.ts       # 代理定义加载
├── agentToolUtils.ts      # 工具函数
├── resumeAgent.ts         # 代理恢复
├── prompt.ts              # 提示词模板
├── UI.tsx                 # UI 组件
└── constants.ts           # 常量定义
│
├── built-in/
│   ├── exploreAgent.ts    # Explore 代理
│   ├── planAgent.ts       # Plan 代理
│   ├── generalPurposeAgent.ts  # 通用代理
│   ├── verificationAgent.ts    # 验证代理
│   ├── claudeCodeGuideAgent.ts # Claude Code 指导代理
│   └── statuslineSetup.ts      # 状态栏设置代理
│
src/coordinator/
├── coordinatorMode.ts     # 协调者模式逻辑
├── workerAgent.ts         # 工作代理定义
```

### 1.3 Agent 定义类型系统

```typescript
// 基础代理定义字段
type BaseAgentDefinition = {
  agentType: string           // 代理类型标识
  whenToUse: string           // 使用场景描述 (显示给主代理)
  tools?: string[]            // 允许的工具列表 ['*'] 表示全部
  disallowedTools?: string[]  // 禁止的工具列表
  skills?: string[]           // 预加载的技能
  mcpServers?: AgentMcpServerSpec[]  // MCP 服务器配置
  hooks?: HooksSettings       // 会话钩子
  color?: AgentColorName      // UI 显示颜色
  model?: 'inherit' | 'haiku' | 'sonnet' | 'opus'  // 模型选择
  effort?: EffortValue        // 努力程度
  permissionMode?: PermissionMode  // 权限模式
  maxTurns?: number           // 最大对话轮次
  background?: boolean        // 是否后台运行
  isolation?: 'worktree' | 'remote'  // 隔离模式
  memory?: AgentMemoryScope   // 记忆范围
  omitClaudeMd?: boolean      // 是否省略 CLAUDE.md
  getSystemPrompt?: () => string  // 系统提示词生成函数
  source: 'built-in' | 'user' | 'plugin' | 'policySettings'  // 来源
  baseDir: string             // 基础目录
}

// 完整代理定义
type AgentDefinition = 
  | BuiltInAgentDefinition    // 内置代理
  | CustomAgentDefinition     // 用户/项目自定义代理
  | PluginAgentDefinition     // 插件提供的代理
```

---

## 2. 内置代理类型详解

### 2.1 Explore Agent (探索代理)

**用途**: 快速代码库搜索和探索

**源码位置**: `src/tools/AgentTool/built-in/exploreAgent.ts`

```typescript
export const EXPLORE_AGENT: BuiltInAgentDefinition = {
  agentType: 'Explore',
  whenToUse: 'Fast agent specialized for exploring codebases. Use this when you need to quickly find files by patterns (eg. "src/components/**/*.tsx"), search code for keywords (eg. "API endpoints"), or answer questions about the codebase (eg. "how do API endpoints work?"). When calling this agent, specify the desired thoroughness level: "quick" for basic searches, "medium" for moderate exploration, or "very thorough" for comprehensive analysis across multiple locations and naming conventions.',
  
  // 禁止的工具 - Explore 是只读代理
  disallowedTools: [
    AGENT_TOOL_NAME,        // 不能再创建子代理 (防止递归)
    EXIT_PLAN_MODE_TOOL_NAME,
    FILE_EDIT_TOOL_NAME,    // 不能编辑文件
    FILE_WRITE_TOOL_NAME,   // 不能写入文件
    NOTEBOOK_EDIT_TOOL_NAME,
  ],
  
  source: 'built-in',
  baseDir: 'built-in',
  
  // 模型选择策略
  model: process.env.USER_TYPE === 'ant' ? 'inherit' : 'haiku',
  
  // 不加载 CLAUDE.md 以节省 token
  omitClaudeMd: true,
  
  getSystemPrompt: () => getExploreSystemPrompt(),
}
```

**系统提示词核心要点**:

```
=== CRITICAL: READ-ONLY MODE - NO FILE MODIFICATIONS ===

This is a READ-ONLY exploration task. You are STRICTLY PROHIBITED from:
- Creating new files
- Modifying existing files
- Deleting files
- Running ANY commands that change system state

Your role is EXCLUSIVELY to search and analyze existing code.

Guidelines:
- Use Glob for broad file pattern matching
- Use Grep for searching file contents with regex
- Use Read when you know the specific file path
- Use Bash ONLY for read-only operations
- NEVER use Bash for: mkdir, touch, rm, cp, mv, git add, git commit...

NOTE: You are meant to be a fast agent that returns output as quickly as possible.
- Make efficient use of tools
- Try to spawn multiple parallel tool calls for grepping and reading files
```

**关键设计要点**:

1. **只读模式**: 所有写入类工具被禁止
2. **快速模型**: 外部用户使用 haiku (快速便宜)
3. **并行搜索**: 提示词强调并行执行多个搜索
4. **彻底性级别**: 支持 quick/medium/very thorough 三级搜索深度

### 2.2 Plan Agent (规划代理)

**用途**: 软件架构设计，生成实现计划

**源码位置**: `src/tools/AgentTool/built-in/planAgent.ts`

```typescript
export const PLAN_AGENT: BuiltInAgentDefinition = {
  agentType: 'Plan',
  whenToUse: 'Software architect agent for designing implementation plans. Use this when you need to plan the implementation strategy for a task. Returns step-by-step plans, identifies critical files, and considers architectural trade-offs.',
  
  disallowedTools: [
    AGENT_TOOL_NAME,
    EXIT_PLAN_MODE_TOOL_NAME,
    FILE_EDIT_TOOL_NAME,
    FILE_WRITE_TOOL_NAME,
    NOTEBOOK_EDIT_TOOL_NAME,
  ],
  
  source: 'built-in',
  tools: EXPLORE_AGENT.tools,  // 继承 Explore 的工具集
  baseDir: 'built-in',
  
  model: 'inherit',  // 继承父代理的模型
  
  omitClaudeMd: true,
  
  getSystemPrompt: () => getPlanV2SystemPrompt(),
}
```

**系统提示词核心流程**:

```
## Your Process

1. **Understand Requirements**: Focus on requirements and apply perspective

2. **Explore Thoroughly**:
   - Read any files provided in the initial prompt
   - Find existing patterns and conventions
   - Understand current architecture
   - Identify similar features as reference
   - Trace through relevant code paths

3. **Design Solution**:
   - Create implementation approach
   - Consider trade-offs and architectural decisions
   - Follow existing patterns where appropriate

4. **Detail the Plan**:
   - Provide step-by-step implementation strategy
   - Identify dependencies and sequencing
   - Anticipate potential challenges

## Required Output

End your response with:

### Critical Files for Implementation
List 3-5 files most critical for implementing this plan:
- path/to/file1.ts
- path/to/file2.ts
```

**与 Explore Agent 的区别**:

| 特性 | Explore | Plan |
|------|---------|------|
| 模型 | haiku (快速) | inherit (父代理模型) |
| 输出 | 搜索结果 | 实现计划 + 关键文件 |
| 深度 | 可配置 thoroughness | 架构分析级别 |
| 目的 | 找文件/代码 | 设计实现方案 |

### 2.3 General Purpose Agent (通用代理)

**用途**: 复杂任务的研究和执行

**源码位置**: `src/tools/AgentTool/built-in/generalPurposeAgent.ts`

```typescript
export const GENERAL_PURPOSE_AGENT: BuiltInAgentDefinition = {
  agentType: 'general-purpose',
  whenToUse: 'General-purpose agent for researching complex questions, searching for code, and executing multi-step tasks. When you are searching for a keyword or file and are not confident that you will find the right match in the first few tries use this agent to perform the search for you.',
  
  tools: ['*'],  // 访问所有工具
  
  source: 'built-in',
  baseDir: 'built-in',
  
  // model 被省略 - 使用 getDefaultSubagentModel()
  getSystemPrompt: getGeneralPurposeSystemPrompt,
}
```

**系统提示词**:

```typescript
const SHARED_PREFIX = `You are an agent for Claude Code, Anthropic's official CLI for Claude. Given the user's message, you should use the tools available to complete the task. Complete the task fully—don't gold-plate, but don't leave it half-done.`

const SHARED_GUIDELINES = `Your strengths:
- Searching for code, configurations, and patterns across large codebases
- Analyzing multiple files to understand system architecture
- Investigating complex questions that require exploring many files
- Performing multi-step research tasks

Guidelines:
- For file searches: search broadly when you don't know where something lives
- For analysis: Start broad and narrow down
- Be thorough: Check multiple locations, consider different naming conventions
- NEVER create files unless absolutely necessary
- NEVER proactively create documentation files (*.md) or README files`
```

**关键特性**:

1. **全工具访问**: `tools: ['*']` 提供所有工具
2. **完整执行**: 提示词强调 "complete the task fully"
3. **简洁报告**: 结果只需 essentials
4. **不创建文档**: 明确禁止主动创建文档文件

### 2.4 Verification Agent (验证代理)

**用途**: 独立验证实现是否正确

**特性标志**: `feature('VERIFICATION_AGENT')` + `tengu_hive_evidence`

**设计理念**:

```
Verification means **proving the code works**, not confirming it exists.

- Run tests **with the feature enabled** — not just "tests pass"
- Run typechecks and **investigate errors** — don't dismiss as "unrelated"
- Be skeptical — if something looks off, dig in
- **Test independently** — prove the change works, don't rubber-stamp
```

### 2.5 Claude Code Guide Agent (指导代理)

**用途**: 回答关于 Claude Code 本身的问题

**触发条件**: 非 SDK 入口点 (`entrypoint !== 'sdk-ts' && !== 'sdk-py' && !== 'sdk-cli'`)

### 2.6 Statusline Setup Agent (状态栏设置代理)

**用途**: 配置状态栏设置

---

## 3. Fork 子代理机制

### 3.1 Fork 概念

**Fork** 是一种轻量级的子代理创建方式，核心特点:

- **上下文继承**: 子代理继承父代理的完整对话历史
- **Prompt Cache 共享**: 确保缓存命中，提高效率
- **快速派生**: 无需重新构建上下文

**与正常 Agent 创建的区别**:

| 特性 | Fork | 正常 Spawn |
|------|------|-----------|
| 上下文 | 继承父代理完整历史 | 从新消息开始 |
| Prompt Cache | 共享 (字节级精确) | 独立构建 |
| 子代理类型 | `fork` (隐式) | 需显式指定 |
| 工具池 | 父代理精确工具池 | 根据代理定义解析 |
| 权限模式 | `bubble` (上浮到父终端) | 独立权限 |

### 3.2 Fork 启用条件

```typescript
export function isForkSubagentEnabled(): boolean {
  if (feature('FORK_SUBAGENT')) {
    if (isCoordinatorMode()) return false  // 与协调者模式互斥
    if (getIsNonInteractiveSession()) return false  // SDK 模式禁用
    return true
  }
  return false
}
```

### 3.3 Fork 代理定义

```typescript
export const FORK_AGENT = {
  agentType: FORK_SUBAGENT_TYPE,  // 'fork'
  whenToUse: 'Implicit fork — inherits full conversation context...',
  tools: ['*'],
  maxTurns: 200,
  model: 'inherit',       // 继承父代理模型
  permissionMode: 'bubble', // 权限提示上浮到父终端
  source: 'built-in',
  baseDir: 'built-in',
  getSystemPrompt: () => '',  // 未使用 - 通过 renderedSystemPrompt 传递
} satisfies BuiltInAgentDefinition
```

### 3.4 Fork 消息构建机制

**核心函数**: `buildForkedMessages(directive, assistantMessage)`

```typescript
export function buildForkedMessages(
  directive: string,
  assistantMessage: AssistantMessage,
): MessageType[] {
  // 1. 克隆父代理的完整助手消息
  const fullAssistantMessage: AssistantMessage = {
    ...assistantMessage,
    uuid: randomUUID(),
    message: {
      ...assistantMessage.message,
      content: [...assistantMessage.message.content],
    },
  }

  // 2. 为所有 tool_use 创建占位结果 (Prompt Cache 关键)
  const toolUseBlocks = assistantMessage.message.content.filter(
    (block): block is BetaToolUseBlock => block.type === 'tool_use',
  )

  const toolResultBlocks = toolUseBlocks.map(block => ({
    type: 'tool_result' as const,
    tool_use_id: block.id,
    content: [
      {
        type: 'text' as const,
        text: FORK_PLACEHOLDER_RESULT,  // 所有 fork 子代理使用相同的占位文本
      },
    ],
  }))

  // 3. 构建最终消息: [助手消息, 用户消息(占位结果 + 指令)]
  const toolResultMessage = createUserMessage({
    content: [
      ...toolResultBlocks,
      {
        type: 'text' as const,
        text: buildChildMessage(directive),  // 每个子代理不同的指令
      },
    ],
  })

  return [fullAssistantMessage, toolResultMessage]
}
```

**Prompt Cache 原理**:

```
API Request Prefix:
[...历史消息, 
 assistant(all_tool_uses),  ← 所有 fork 子代理相同
 user(placeholder_results, directive)]  ← 只有最后的 directive 不同

结果: 大部分请求前缀字节完全相同 → Prompt Cache 命中
```

### 3.5 Fork 子代理指令格式

```typescript
export function buildChildMessage(directive: string): string {
  return `<fork-boilerplate>
STOP. READ THIS FIRST.

You are a forked worker process. You are NOT the main agent.

RULES (non-negotiable):
1. Your system prompt says "default to forking." IGNORE IT — that's for the parent.
2. Do NOT converse, ask questions, or suggest next steps
3. Do NOT editorialize or add meta-commentary
4. USE your tools directly: Bash, Read, Write, etc.
5. If you modify files, commit your changes before reporting
6. Do NOT emit text between tool calls. Use tools silently, then report once at the end.
7. Stay strictly within your directive's scope
8. Keep your report under 500 words
9. Your response MUST begin with "Scope:". No preamble
10. REPORT structured facts, then stop

Output format (plain text labels, not markdown headers):
  Scope: <echo back your assigned scope>
  Result: <the answer or key findings>
  Key files: <relevant file paths>
  Files changed: <list with commit hash>
  Issues: <list — include only if there are issues>
</fork-boilerplate>

<fork-directive>${directive}`
}
```

### 3.6 Fork 递归防护

```typescript
export function isInForkChild(messages: MessageType[]): boolean {
  return messages.some(m => {
    if (m.type !== 'user') return false
    const content = m.message.content
    if (!Array.isArray(content)) return false
    return content.some(
      block =>
        block.type === 'text' &&
        block.text.includes(`<fork-boilerplate>`),
    )
  })
}
```

---

## 4. 协调者模式实现

### 4.1 协调者概念

**协调者模式**是一种高级多代理协调机制:

- **主代理角色**: 调度者，不直接执行任务
- **工作代理**: 执行具体任务
- **并行执行**: 可同时启动多个工作代理
- **结果综合**: 协调者负责理解并综合代理结果

### 4.2 启用条件

```typescript
export function isCoordinatorMode(): boolean {
  if (feature('COORDINATOR_MODE')) {
    return isEnvTruthy(process.env.CLAUDE_CODE_COORDINATOR_MODE)
  }
  return false
}
```

### 4.3 协调者系统提示词

```typescript
export function getCoordinatorSystemPrompt(): string {
  return `You are Claude Code, an AI assistant that orchestrates software engineering tasks across multiple workers.

## 1. Your Role

You are a **coordinator**. Your job is to:
- Help the user achieve their goal
- Direct workers to research, implement and verify code changes
- Synthesize results and communicate with the user
- Answer questions directly when possible

Every message you send is to the user. Worker results and system notifications are internal signals — never thank or acknowledge them.

## 2. Your Tools

- **Agent** - Spawn a new worker
- **SendMessage** - Continue an existing worker
- **TaskStop** - Stop a running worker

## 3. Workers

Workers have access to standard tools, MCP tools, and project skills.

## 4. Task Workflow

| Phase | Who | Purpose |
|-------|-----|---------|
| Research | Workers (parallel) | Investigate codebase |
| Synthesis | **You** (coordinator) | Understand and plan |
| Implementation | Workers | Make targeted changes |
| Verification | Workers | Test changes work |

**Parallelism is your superpower. Workers are async.**`
}
```

### 4.4 任务通知格式

工作代理结果以 XML 格式返回:

```xml
<task-notification>
<task-id>{agentId}</task-id>
<status>completed|failed|killed</status>
<summary>{human-readable status summary}</summary>
<result>{agent's final text response}</result>
<usage>
  <total_tokens>N</total_tokens>
  <tool_uses>N</tool_uses>
  <duration_ms>N</duration_ms>
</usage>
</task-notification>
```

### 4.5 协调者工作流程

```
用户请求: "修复 auth 模块的空指针"
           ↓
┌────────────────────────────────────────┐
│ 协调者分析请求                          │
│ 需要研究 → 启动多个并行工作代理          │
└────────────────────────────────────────┘
           ↓
┌─────────────────────┐  ┌─────────────────────┐
│ Worker 1            │  │ Worker 2            │
│ Investigate auth bug│  │ Research auth tests │
│ (研究代码)          │  │ (研究测试结构)      │
└─────────────────────┘  └─────────────────────┘
           ↓                      ↓
<task-notification>      <task-notification>
(找到 validate.ts:42)    (测试覆盖范围)
           ↓                      ↓
┌────────────────────────────────────────┐
│ 协调者综合结果                          │
│ "在 validate.ts:42 发现空指针"          │
│ 决定修复策略                            │
└────────────────────────────────────────┘
           ↓
┌─────────────────────┐
│ Worker 3            │
│ Fix null pointer    │
│ (执行修复)          │
└─────────────────────┘
           ↓
<task-notification>
(修复完成, commit hash: abc123)
           ↓
┌────────────────────────────────────────┐
│ 协调者向用户报告                        │
│ "已修复 validate.ts:42 的空指针"        │
│ "commit: abc123"                       │
└────────────────────────────────────────┘
```

### 4.6 协调者提示词关键原则

**1. 综合而非委托**

```
// 错误: 懒惰委托
Agent({ prompt: "Based on your findings, fix the auth bug" })

// 正确: 先综合再委托
Agent({ prompt: "Fix the null pointer in src/auth/validate.ts:42. 
The user field is undefined when Session.expired is true. 
Add a null check before accessing user.id — if null, return 401." })
```

**2. Continue vs Spawn 选择**

| 情况 | 选择 | 原因 |
|------|------|------|
| 研究恰好覆盖需要编辑的文件 | **Continue** | 工作代理已有上下文 |
| 研究宽泛但实现窄 | **Spawn fresh** | 避免携带无关上下文 |
| 修正失败 | **Continue** | 有错误上下文 |
| 验证其他代理的实现 | **Spawn fresh** | 需要独立视角 |

---

## 5. runAgent 核心执行引擎

### 5.1 函数签名

```typescript
export async function* runAgent({
  agentDefinition,
  promptMessages,
  toolUseContext,
  canUseTool,
  isAsync,
  canShowPermissionPrompts,
  forkContextMessages,
  querySource,
  override,
  model,
  maxTurns,
  preserveToolUseResults,
  availableTools,
  allowedTools,
  onCacheSafeParams,
  contentReplacementState,
  useExactTools,
  worktreePath,
  description,
  transcriptSubdir,
  onQueryProgress,
}: RunAgentParams): AsyncGenerator<Message, void>
```

### 5.2 核心执行流程

```typescript
export async function* runAgent({...}): AsyncGenerator<Message, void> {
  // ═══════════════════════════════════════════
  // 阶段 1: 初始化代理 ID 和状态
  // ═══════════════════════════════════════════
  const agentId = override?.agentId ?? createAgentId()
  const appState = toolUseContext.getAppState()
  const permissionMode = appState.toolPermissionContext.mode
  
  // 解析模型
  const resolvedAgentModel = getAgentModel(
    agentDefinition.model,
    toolUseContext.options.mainLoopModel,
    model,
    permissionMode,
  )

  // ═══════════════════════════════════════════
  // 阶段 2: 初始化代理专用 MCP 服务器
  // ═══════════════════════════════════════════
  const { clients, tools, cleanup } = await initializeAgentMcpServers(
    agentDefinition,
    parentClients,
  )

  // ═══════════════════════════════════════════
  // 阶段 3: 解析工具池
  // ═══════════════════════════════════════════
  const agentTools = useExactTools 
    ? availableTools 
    : resolveAgentTools(agentDefinition, parentTools, mcpTools)

  // ═══════════════════════════════════════════
  // 阶段 4: 创建子代理上下文
  // ═══════════════════════════════════════════
  const subContext = createSubagentContext(
    toolUseContext,
    agentId,
    agentDefinition,
    {
      tools: agentTools,
      model: resolvedAgentModel,
      permissionMode: effectivePermissionMode,
      // ... 更多配置
    }
  )

  // ═══════════════════════════════════════════
  // 阶段 5: 构建系统提示词
  // ═══════════════════════════════════════════
  const systemPrompt = override?.systemPrompt 
    ?? asSystemPrompt(agentDefinition.getSystemPrompt?.() ?? '')

  // 添加环境细节
  const enhancedSystemPrompt = enhanceSystemPromptWithEnvDetails(
    systemPrompt,
    agentDefinition,
    subContext,
  )

  // ═══════════════════════════════════════════
  // 阶段 6: 执行查询循环
  // ═══════════════════════════════════════════
  for await (const event of query({
    messages: initialMessages,
    systemPrompt: enhancedSystemPrompt,
    tools: agentTools,
    context: subContext,
    canUseTool: subCanUseTool,
    model: resolvedAgentModel,
    maxTurns: effectiveMaxTurns,
    // ... 更多参数
  })) {
    // 过滤并 yield 可记录的消息
    if (isRecordableMessage(event)) {
      yield event
    }
  }

  // ═══════════════════════════════════════════
  // 阶段 7: 清理资源
  // ═══════════════════════════════════════════
  await cleanup()  // 清理 MCP 服务器
  cleanupAgentTracking(agentId)  // 清理跟踪
}
```

### 5.3 MCP 服务器初始化

```typescript
async function initializeAgentMcpServers(
  agentDefinition: AgentDefinition,
  parentClients: MCPServerConnection[],
): Promise<{
  clients: MCPServerConnection[]
  tools: Tools
  cleanup: () => Promise<void>
}> {
  // 无代理专用服务器 → 返回父客户端
  if (!agentDefinition.mcpServers?.length) {
    return {
      clients: parentClients,
      tools: [],
      cleanup: async () => {},
    }
  }

  const agentClients: MCPServerConnection[] = []
  const newlyCreatedClients: MCPServerConnection[] = []
  const agentTools: Tool[] = []

  for (const spec of agentDefinition.mcpServers) {
    if (typeof spec === 'string') {
      // 引用现有 MCP 配置
      config = getMcpConfigByName(spec)
    } else {
      // 内联定义的新服务器
      const [serverName, serverConfig] = Object.entries(spec)[0]
      config = { ...serverConfig, scope: 'dynamic' }
      isNewlyCreated = true
    }

    // 连接服务器
    const client = await connectToServer(name, config)
    agentClients.push(client)
    
    if (isNewlyCreated) {
      newlyCreatedClients.push(client)
    }

    // 获取工具
    if (client.type === 'connected') {
      const tools = await fetchToolsForClient(client)
      agentTools.push(...tools)
    }
  }

  // 清理函数 - 只清理新创建的客户端
  const cleanup = async () => {
    for (const client of newlyCreatedClients) {
      if (client.type === 'connected') {
        await client.cleanup()
      }
    }
  }

  return {
    clients: [...parentClients, ...agentClients],
    tools: agentTools,
    cleanup,
  }
}
```

---

## 6. Agent 工具输入与参数

### 6.1 输入 Schema

```typescript
const baseInputSchema = z.object({
  // 基本信息
  description: z.string()
    .describe('A short (3-5 word) description of the task'),
  
  prompt: z.string()
    .describe('The task for the agent to perform'),
  
  // 代理类型
  subagent_type: z.string().optional()
    .describe('The type of specialized agent to use'),
  
  // 模型选择
  model: z.enum(['sonnet', 'opus', 'haiku']).optional(),
  
  // 运行模式
  run_in_background: z.boolean().optional()
    .describe('Set to true to run this agent in the background'),
})

// 多代理扩展
const multiAgentInputSchema = z.object({
  name: z.string().optional()
    .describe('Name for the spawned agent'),
  
  team_name: z.string().optional()
    .describe('Team name for spawning multiple agents'),
  
  mode: permissionModeSchema().optional()
    .describe('Permission mode override'),
  
  isolation: z.enum(['worktree', 'remote']).optional()
    .describe('Isolation mode for the agent'),
})
```

### 6.2 参数详解

| 参数 | 类型 | 说明 |
|------|------|------|
| `description` | string | 3-5 词任务描述，用于 UI 显示 |
| `prompt` | string | 完整任务指令，发给子代理 |
| `subagent_type` | string | 代理类型: Explore, Plan, general-purpose 等 |
| `model` | enum | 模型选择: sonnet, opus, haiku |
| `run_in_background` | boolean | 后台运行，结果通过 `<task-notification>` 返回 |
| `name` | string | 代理名称，用于标识 |
| `isolation` | enum | worktree: Git 工作树隔离; remote: 远程执行 |

### 6.3 调用示例

**探索代理**:

```typescript
Agent({
  description: "Find API endpoints",
  subagent_type: "Explore",
  prompt: "Find all API endpoints in the codebase. Look for route definitions, controller files, and REST handlers. Report file paths and endpoint patterns.",
  model: "haiku"
})
```

**规划代理**:

```typescript
Agent({
  description: "Plan auth refactor",
  subagent_type: "Plan",
  prompt: "Plan the implementation for refactoring the auth module to use JWT instead of sessions. Consider the current architecture in src/auth/, identify files that need changes, and design the migration strategy.",
})
```

**通用代理 (后台)**:

```typescript
Agent({
  description: "Investigate memory leak",
  run_in_background: true,
  prompt: "Investigate potential memory leak in the WebSocket handler. Check src/websocket/, look for unclosed connections, event listener accumulation, and resource cleanup patterns.",
})
```

---

## 7. Agent 与 MCP 集成

### 7.1 MCP 服务器配置

代理可以定义自己的 MCP 服务器:

```typescript
// 代理定义中的 MCP 配置
{
  agentType: 'data-analyst',
  mcpServers: [
    // 引用现有配置
    'postgres-server',
    
    // 内联定义新服务器
    {
      'custom-analytics': {
        type: 'stdio',
        command: 'python',
        args: ['analytics_server.py'],
      }
    }
  ]
}
```

### 7.2 MCP 工具继承

```
父代理 MCP 工具
      ↓
┌─────────────────────────────┐
│ 代理启动时合并              │
│ parentClients + agentClients │
└─────────────────────────────┘
      ↓
完整工具池 = 内置工具 + MCP工具 + 代理专用MCP工具
```

### 7.3 MCP 工具命名

MCP 工具使用前缀命名: `mcp__{serverName}__{toolName}`

例如:
- `mcp__postgres__query`
- `mcp__filesystem__read_file`

---

## 8. Agent 生命周期管理

### 8.1 生命周期状态

```
创建 → 运行 → 完成/失败/终止 → 清理
 ↓       ↓        ↓            ↓
pending  running  completed    cleanup()
                  failed
                  killed
```

### 8.2 会话存储结构

```
~/.claude/
├── sessions/
│   └── {session-id}/
│       ├── transcript.jsonl    # 主会话对话
│       └── metadata.json       # 元数据
│
├── subagents/
│   └── {agent-id}/
│       ├── transcript.jsonl    # 子代理对话
│       └── metadata.json       # 代理元数据
│           ├── agentType
│           ├── description
│           ├── worktreePath
│           └── status
```

### 8.3 代理恢复机制

```typescript
// resumeAgent.ts
export async function resumeAgent(agentId: AgentId): Promise<void> {
  // 1. 读取代理元数据
  const metadata = await readAgentMetadata(agentId)
  
  // 2. 加载对话历史
  const transcript = await readTranscript(agentId)
  
  // 3. 恢复 MCP 连接
  const clients = await reconnectMcpServers(metadata.mcpServers)
  
  // 4. 恢复工作树 (如果使用 isolation: worktree)
  if (metadata.worktreePath) {
    await verifyWorktree(metadata.worktreePath)
  }
  
  // 5. 继续查询循环
  return runAgent({
    agentDefinition: metadata.agentDefinition,
    promptMessages: transcript,
    // ...恢复的状态
  })
}
```

### 8.4 任务终止

```typescript
// TaskStop 工具
{
  name: 'TaskStop',
  call: async ({ task_id }) => {
    // 1. 找到代理
    const agent = getAgentById(task_id)
    
    // 2. 设置终止标志
    agent.abortController.abort()
    
    // 3. 清理 Shell 任务
    await killShellTasksForAgent(task_id)
    
    // 4. 清理 MCP
    await agent.cleanup()
    
    // 5. 更新状态
    agent.status = 'killed'
  }
}
```

---

## 9. 实际应用案例

### 9.1 案例: 多文件重构

**场景**: 重构认证系统

```typescript
// 协调者模式下的执行
User: "Refactor auth module to use JWT"

Coordinator:
  // 阶段 1: 并行研究
  Agent({
    description: "Research auth architecture",
    subagent_type: "Explore",
    prompt: "Explore src/auth/ directory. Find current session management implementation, token handling, and all files that reference auth functions.",
  })
  
  Agent({
    description: "Research JWT patterns",
    subagent_type: "Explore", 
    prompt: "Search codebase for any existing JWT implementations or patterns. Look for JWT libraries, token generation patterns, and similar authentication schemes.",
  })
  
  "Starting parallel research..."

// 研究完成
<task-notification>
  agent-id: agent-a1
  result: Found session management in src/auth/session.ts, 
          token in src/auth/token.ts,
          23 files reference auth functions...
</task-notification>

Coordinator:
  // 阶段 2: 综合并规划
  Agent({
    description: "Plan JWT implementation",
    subagent_type: "Plan",
    prompt: "Based on research findings, plan JWT refactor for src/auth/. 
    Current: session.ts handles session management, token.ts handles tokens.
    Target: Replace session with JWT. 
    Files to modify: src/auth/session.ts, src/auth/token.ts, 
    src/middleware/auth.ts, src/controllers/*.ts.
    Output implementation steps and critical files.",
  })
  
// 规划完成
<task-notification>
  result: Implementation plan:
    1. Create JWTService in src/auth/jwt.ts
    2. Update token.ts to use JWTService
    3. Remove session.ts, update middleware
    Critical files: src/auth/session.ts, src/middleware/auth.ts...
</task-notification>

Coordinator:
  // 阶段 3: 实现
  Agent({
    description: "Implement JWT service",
    prompt: "Create src/auth/jwt.ts with JWTService class. 
    Use existing patterns from src/auth/token.ts.
    Include generateToken, validateToken, refreshToken methods.
    Follow existing error handling patterns in src/auth/",
  })
  
  "Implementing JWT service..."

// 实现完成
<task-notification>
  result: Created src/auth/jwt.ts with JWTService.
  Commit: abc123
</task-notification>

Coordinator:
  // 阶段 4: 验证
  Agent({
    description: "Verify JWT implementation",
    prompt: "Verify the JWT implementation works correctly.
    Run tests in src/auth/tests/, check JWT token generation,
    validation flow. Test edge cases: expired tokens, invalid signatures.",
  })
```

### 9.2 案例: Fork 并行搜索

```typescript
// Fork 模式下并行搜索
Main Agent:
  "I need to find all references to the deprecated API"
  
  Agent({
    description: "Find API client usage",
    run_in_background: true,
    // 无 subagent_type → Fork 路径
    prompt: "Search for all client-side API calls using the deprecated endpoints. Look in src/client/, src/pages/, and src/components/",
  })
  
  Agent({
    description: "Find API server routes",
    run_in_background: true,
    prompt: "Search for all server-side route definitions for deprecated endpoints. Look in src/routes/, src/controllers/",
  })
  
  Agent({
    description: "Find API documentation",
    run_in_background: true,
    prompt: "Search for documentation referencing deprecated API. Look in docs/, README files, and comments",
  })

// 三个 Fork 子代理共享 Prompt Cache
// 只有最后的 directive 不同 → 高缓存命中率
```

---

## 10. 设计模式与最佳实践

### 10.1 设计模式总结

**1. 分层委托模式**

```
用户 → 主代理 → 子代理 → 工具
       (协调者)   (工作者)   (执行者)
```

**2. 上下文隔离模式**

每个子代理有独立上下文，防止污染父代理

**3. Prompt Cache 共享模式**

Fork 机制确保字节级精确的前缀匹配

**4. 结果通知模式**

`<task-notification>` XML 格式标准化结果传递

### 10.2 最佳实践

**代理选择指南**:

| 任务类型 | 推荐代理 | 原因 |
|----------|----------|------|
| 快速文件搜索 | Explore | haiku 快速，只读安全 |
| 架构规划 | Plan | 架构师视角，输出计划 |
| 复杂实现 | general-purpose | 全工具访问 |
| 独立验证 | Verification | 独立视角验证 |
| 并行子任务 | Fork | 缓存共享，快速派生 |

**提示词编写原则**:

1. **自包含**: 子代理看不到主代理对话，提示词必须完整
2. **具体**: 包含文件路径、行号、具体变更
3. **目标明确**: 说明"完成"的标准
4. **范围限定**: 防止代理过度探索

**避免的错误**:

```
// ❌ 错误: 模糊指令
"Fix the bug we discussed"

// ✅ 正确: 具体指令
"Fix null pointer in src/auth/validate.ts:42.
The user field is undefined when Session.expired is true.
Add null check before user.id access.
Commit and report hash."

// ❌ 错误: 委托综合
"Based on findings, fix it"

// ✅ 正确: 主代理先综合
Agent({
  prompt: "Fix null pointer in validate.ts:42.
  Add check: if (!session.user) return 401 'Session expired'.
  Run tests, commit, report hash."
})
```

---

## 附录: Agent 系统关键常量

```typescript
// 工具名称
export const AGENT_TOOL_NAME = 'Agent'
export const SEND_MESSAGE_TOOL_NAME = 'SendMessage'
export const TASK_STOP_TOOL_NAME = 'TaskStop'

// Fork 相关
export const FORK_SUBAGENT_TYPE = 'fork'
export const FORK_BOILERPLATE_TAG = 'fork-boilerplate'
export const FORK_DIRECTIVE_PREFIX = 'fork-directive:'
export const FORK_PLACEHOLDER_RESULT = 'Fork started — processing in background'

// 任务状态
export type TaskStatus = 'pending' | 'running' | 'completed' | 'failed' | 'killed'

// 任务类型
export type TaskType =
  | 'local_bash'
  | 'local_agent'
  | 'remote_agent'
  | 'in_process_teammate'
  | 'local_workflow'
  | 'monitor_mcp'
  | 'dream'
```

---

*文档版本: 1.0*
*最后更新: 2026-03-31*
*作者: Claude Code 分析系统*