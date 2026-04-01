# Claude Code MCP 与扩展系统深度技术文档

> 版本: 2.1.88
> 目的: 为开发者提供 MCP 系统的完整实现细节和学习参考

---

## 目录

1. [MCP 系统架构总览](#1-mcp-系统架构总览)
2. [传输层类型详解](#2-传输层类型详解)
3. [客户端连接流程](#3-客户端连接流程)
4. [工具注册与发现](#4-工具注册与发现)
5. [OAuth 认证机制](#5-oauth-认证机制)
6. [MCP 服务端实现](#6-mcp-服务端实现)
7. [错误处理与重连](#7-错误处理与重连)
8. [设计模式与最佳实践](#8-设计模式与最佳实践)

---

## 1. MCP 系统架构总览

### 1.1 核心设计理念

Claude Code 的 MCP (Model Context Protocol) 系统采用了**多传输层 + 统一抽象**的设计:

```
用户请求 → MCP 工具调用 → 传输层适配 → MCP 服务器 → 工具执行
                               ↓
                    ┌──────────┼──────────┐
                    │          │          │
                 stdio      sse/http    ws/sdk
                 本地进程    远程服务    IDE集成
```

**关键设计原则:**

1. **传输无关**: 工具调用逻辑与传输层解耦
2. **类型安全**: 使用 Zod schema 进行运行时验证
3. **连接复用**: Memoization 缓存避免重复连接
4. **优雅降级**: 认证失败时提供明确的状态反馈
5. **策略过滤**: 支持企业级的允许/拒绝规则

### 1.2 核心文件结构

```
src/services/mcp/
├── client.ts              # 客户端连接核心 (2000+ 行)
├── types.ts               # 类型定义 (260+ 行)
├── config.ts              # 配置管理 (1580+ 行)
├── auth.ts                # OAuth 认证 (2470+ 行)
├── InProcessTransport.ts  # 进程内传输
├── SdkControlTransport.ts # SDK 控制传输
├── headersHelper.ts       # 请求头处理
├── envExpansion.ts        # 环境变量扩展
├── normalization.ts       # 名称规范化
├── utils.ts               # 工具函数
├── claudeai.ts            # Claude.ai 代理
├── xaa.ts                 # 跨应用访问
├── xaaIdpLogin.ts         # XAA IdP 登录
├── oauthPort.ts           # OAuth 端口管理
├── elicitationHandler.ts  # 交互请求处理
└── channelPermissions.ts  # 通道权限

src/tools/
├── MCPTool/
│   ├── MCPTool.ts         # MCP 工具实现
│   ├── prompt.ts          # 提示词模板
│   ├── UI.tsx             # UI 组件
│   └── classifyForCollapse.ts  # 折叠分类
│
├── ListMcpResourcesTool/
│   ├── ListMcpResourcesTool.ts  # 资源列表工具
│   ├── prompt.ts                # 提示词
│   └── UI.tsx                   # UI 组件
│
├── ReadMcpResourceTool/
│   └── ReadMcpResourceTool.ts   # 资源读取工具
│
└── McpAuthTool/
    └── McpAuthTool.ts           # 认证工具
```

### 1.3 MCP 连接状态类型

```typescript
// 连接状态类型
export type MCPServerConnection =
  | ConnectedMCPServer    // 已连接
  | FailedMCPServer       // 连接失败
  | NeedsAuthMCPServer    // 需要认证
  | PendingMCPServer      // 等待中
  | DisabledMCPServer     // 已禁用

// 已连接服务器
export type ConnectedMCPServer = {
  client: Client                    // MCP SDK 客户端
  name: string                      // 服务器名称
  type: 'connected'                 // 状态类型
  capabilities: ServerCapabilities  // 服务器能力
  serverInfo?: {                    // 服务器信息
    name: string
    version: string
  }
  instructions?: string             // 服务器指令
  config: ScopedMcpServerConfig     // 作用域配置
  cleanup: () => Promise<void>      // 清理函数
}

// 需要认证的服务器
export type NeedsAuthMCPServer = {
  name: string
  type: 'needs-auth'
  config: ScopedMcpServerConfig
}

// 连接失败的服务器
export type FailedMCPServer = {
  name: string
  type: 'failed'
  config: ScopedMcpServerConfig
  error?: string
}
```

---

## 2. 传输层类型详解

### 2.1 传输类型 Schema 定义

```typescript
export const TransportSchema = lazySchema(() =>
  z.enum(['stdio', 'sse', 'sse-ide', 'http', 'ws', 'ws-ide', 'sdk']),
)

export type Transport = z.infer<ReturnType<typeof TransportSchema>>
```

### 2.2 Stdio 传输 (本地进程)

**配置 Schema:**

```typescript
export const McpStdioServerConfigSchema = lazySchema(() =>
  z.object({
    type: z.literal('stdio').optional(),  // 可选，向后兼容
    command: z.string().min(1, 'Command cannot be empty'),
    args: z.array(z.string()).default([]),
    env: z.record(z.string(), z.string()).optional(),
  }),
)

export type McpStdioServerConfig = {
  type?: 'stdio'
  command: string        // 可执行命令
  args: string[]         // 命令参数
  env?: Record<string, string>  // 环境变量
}
```

**连接实现:**

```typescript
// client.ts - Stdio 连接
if (serverRef.type === 'stdio' || !serverRef.type) {
  const finalCommand = process.env.CLAUDE_CODE_SHELL_PREFIX || serverRef.command
  const finalArgs = process.env.CLAUDE_CODE_SHELL_PREFIX
    ? [[serverRef.command, ...serverRef.args].join(' ')]
    : serverRef.args
    
  transport = new StdioClientTransport({
    command: finalCommand,
    args: finalArgs,
    env: {
      ...subprocessEnv(),
      ...serverRef.env,
    } as Record<string, string>,
    stderr: 'pipe',  // 捕获错误输出
  })
}
```

**特点:**

1. **本地进程**: 通过 stdin/stdout 与子进程通信
2. **环境变量继承**: 合并父进程环境与配置
3. **错误捕获**: stderr 管道化防止污染 UI
4. **Shell 前缀**: 支持 `CLAUDE_CODE_SHELL_PREFIX` 环境变量

### 2.3 SSE 传输 (Server-Sent Events)

**配置 Schema:**

```typescript
export const McpSSEServerConfigSchema = lazySchema(() =>
  z.object({
    type: z.literal('sse'),
    url: z.string(),
    headers: z.record(z.string(), z.string()).optional(),
    headersHelper: z.string().optional(),
    oauth: McpOAuthConfigSchema().optional(),
  }),
)

export type McpSSEServerConfig = {
  type: 'sse'
  url: string                              // SSE 端点 URL
  headers?: Record<string, string>         // 自定义请求头
  headersHelper?: string                   // 动态头助手
  oauth?: McpOAuthConfig                   // OAuth 配置
}
```

**连接实现:**

```typescript
if (serverRef.type === 'sse') {
  // 创建认证提供者
  const authProvider = new ClaudeAuthProvider(name, serverRef)
  
  // 获取组合请求头
  const combinedHeaders = await getMcpServerHeaders(name, serverRef)
  
  // SSE 传输选项
  const transportOptions: SSEClientTransportOptions = {
    authProvider,
    fetch: wrapFetchWithTimeout(
      wrapFetchWithStepUpDetection(createFetchWithInit(), authProvider),
    ),
    requestInit: {
      headers: {
        'User-Agent': getMCPUserAgent(),
        ...combinedHeaders,
      },
    },
    // EventSource 使用不带超时的 fetch
    eventSourceInit: {
      fetch: async (url: string | URL, init?: RequestInit) => {
        const authHeaders: Record<string, string> = {}
        const tokens = await authProvider.tokens()
        if (tokens) {
          authHeaders.Authorization = `Bearer ${tokens.access_token}`
        }
        return fetch(url, {
          ...init,
          headers: {
            'User-Agent': getMCPUserAgent(),
            ...authHeaders,
            ...init?.headers,
            Accept: 'text/event-stream',
          },
        })
      },
    },
  }
  
  transport = new SSEClientTransport(
    new URL(serverRef.url),
    transportOptions,
  )
}
```

**特点:**

1. **长连接**: EventSource 保持持久连接
2. **认证集成**: 支持 OAuth 2.0 Bearer Token
3. **超时分离**: POST 请求有超时，GET 流无超时
4. **Step-Up 检测**: 自动处理权限升级请求

### 2.4 HTTP 传输 (Streamable HTTP)

**配置 Schema:**

```typescript
export const McpHTTPServerConfigSchema = lazySchema(() =>
  z.object({
    type: z.literal('http'),
    url: z.string(),
    headers: z.record(z.string(), z.string()).optional(),
    headersHelper: z.string().optional(),
    oauth: McpOAuthConfigSchema().optional(),
  }),
)
```

**连接实现:**

```typescript
if (serverRef.type === 'http') {
  const authProvider = new ClaudeAuthProvider(name, serverRef)
  const combinedHeaders = await getMcpServerHeaders(name, serverRef)
  const hasOAuthTokens = !!(await authProvider.tokens())
  
  const transportOptions: StreamableHTTPClientTransportOptions = {
    authProvider,
    fetch: wrapFetchWithTimeout(
      wrapFetchWithStepUpDetection(createFetchWithInit(), authProvider),
    ),
    requestInit: {
      headers: {
        'User-Agent': getMCPUserAgent(),
        // 会话入口令牌 (用于 CCR 代理)
        ...(sessionIngressToken && !hasOAuthTokens && {
          Authorization: `Bearer ${sessionIngressToken}`,
        }),
        ...combinedHeaders,
      },
    },
  }
  
  transport = new StreamableHTTPClientTransport(
    new URL(serverRef.url),
    transportOptions,
  )
}
```

**关键常量:**

```typescript
// MCP Streamable HTTP 规范要求的 Accept 头
const MCP_STREAMABLE_HTTP_ACCEPT = 'application/json, text/event-stream'

// 请求超时 (60 秒)
const MCP_REQUEST_TIMEOUT_MS = 60000
```

### 2.5 WebSocket 传输

**配置 Schema:**

```typescript
export const McpWebSocketServerConfigSchema = lazySchema(() =>
  z.object({
    type: z.literal('ws'),
    url: z.string(),
    headers: z.record(z.string(), z.string()).optional(),
    headersHelper: z.string().optional(),
  }),
)
```

**连接实现:**

```typescript
if (serverRef.type === 'ws') {
  const combinedHeaders = await getMcpServerHeaders(name, serverRef)
  const tlsOptions = getWebSocketTLSOptions()
  
  const wsHeaders = {
    'User-Agent': getMCPUserAgent(),
    ...(sessionIngressToken && {
      Authorization: `Bearer ${sessionIngressToken}`,
    }),
    ...combinedHeaders,
  }
  
  let wsClient: WsClientLike
  if (typeof Bun !== 'undefined') {
    // Bun WebSocket 支持 headers/proxy/tls
    wsClient = new globalThis.WebSocket(serverRef.url, {
      protocols: ['mcp'],
      headers: wsHeaders,
      proxy: getWebSocketProxyUrl(serverRef.url),
      tls: tlsOptions || undefined,
    } as unknown as string[])
  } else {
    // Node.js 使用 ws 库
    wsClient = await createNodeWsClient(serverRef.url, {
      headers: wsHeaders,
      agent: getWebSocketProxyAgent(serverRef.url),
      ...(tlsOptions || {}),
    })
  }
  
  transport = new WebSocketTransport(wsClient)
}
```

### 2.6 SDK 传输 (进程内)

**配置 Schema:**

```typescript
export const McpSdkServerConfigSchema = lazySchema(() =>
  z.object({
    type: z.literal('sdk'),
    name: z.string(),
  }),
)
```

**特点:**

1. **进程内运行**: 不启动外部进程
2. **IDE 集成**: 用于 VS Code 等 IDE 扩展
3. **控制消息路由**: 通过 SDK 控制传输

### 2.7 IDE 专用传输

**SSE-IDE:**

```typescript
export type McpSSEIDEServerConfig = {
  type: 'sse-ide'
  url: string
  ideName: string                // IDE 名称
  ideRunningInWindows?: boolean  // Windows 运行标志
}
```

**WS-IDE:**

```typescript
export type McpWebSocketIDEServerConfig = {
  type: 'ws-ide'
  url: string
  ideName: string
  authToken?: string             // 认证令牌
  ideRunningInWindows?: boolean
}
```

### 2.8 Claude.ai 代理传输

```typescript
export type McpClaudeAIProxyServerConfig = {
  type: 'claudeai-proxy'
  url: string
  id: string                     // 服务器 ID
}
```

**连接实现:**

```typescript
if (serverRef.type === 'claudeai-proxy') {
  const tokens = getClaudeAIOAuthTokens()
  if (!tokens) {
    throw new Error('No claude.ai OAuth token found')
  }
  
  const oauthConfig = getOauthConfig()
  const proxyUrl = `${oauthConfig.MCP_PROXY_URL}${oauthConfig.MCP_PROXY_PATH.replace('{server_id}', serverRef.id)}`
  
  const fetchWithAuth = createClaudeAiProxyFetch(globalThis.fetch)
  
  const transportOptions: StreamableHTTPClientTransportOptions = {
    fetch: wrapFetchWithTimeout(fetchWithAuth),
    requestInit: {
      headers: {
        'User-Agent': getMCPUserAgent(),
        'X-Mcp-Client-Session-Id': getSessionId(),
      },
    },
  }
  
  transport = new StreamableHTTPClientTransport(
    new URL(proxyUrl),
    transportOptions,
  )
}
```

---

## 3. 客户端连接流程

### 3.1 连接入口函数

```typescript
export const connectToServer = memoize(
  async (
    name: string,
    serverRef: ScopedMcpServerConfig,
    serverStats?: {
      totalServers: number
      stdioCount: number
      sseCount: number
      httpCount: number
      sseIdeCount: number
      wsIdeCount: number
    },
  ): Promise<MCPServerConnection> => {
    // 连接逻辑...
  },
  getServerCacheKey,  // 缓存键函数
)
```

### 3.2 完整连接流程

```typescript
async function connectToServer(name, serverRef, serverStats) {
  // ═══════════════════════════════════════════
  // 阶段 1: 创建传输层
  // ═══════════════════════════════════════════
  let transport
  let inProcessServer
  
  switch (serverRef.type) {
    case 'stdio':
    case undefined:
      // 处理特殊服务器 (Chrome MCP, Computer Use)
      if (isClaudeInChromeMCPServer(name)) {
        inProcessServer = createClaudeForChromeMcpServer(context)
        const [clientTransport, serverTransport] = createLinkedTransportPair()
        await inProcessServer.connect(serverTransport)
        transport = clientTransport
      } else {
        transport = new StdioClientTransport({...})
      }
      break
    case 'sse':
      transport = new SSEClientTransport(...)
      break
    case 'http':
      transport = new StreamableHTTPClientTransport(...)
      break
    case 'ws':
      transport = new WebSocketTransport(...)
      break
    // ... 其他类型
  }
  
  // ═══════════════════════════════════════════
  // 阶段 2: 创建 MCP 客户端
  // ═══════════════════════════════════════════
  const client = new Client(
    {
      name: 'claude-code',
      title: 'Claude Code',
      version: MACRO.VERSION ?? 'unknown',
      description: "Anthropic's agentic coding tool",
      websiteUrl: PRODUCT_URL,
    },
    {
      capabilities: {
        roots: {},
        elicitation: {},
      },
    },
  )
  
  // ═══════════════════════════════════════════
  // 阶段 3: 设置请求处理器
  // ═══════════════════════════════════════════
  client.setRequestHandler(ListRootsRequestSchema, async () => {
    return {
      roots: [{ uri: `file://${getOriginalCwd()}` }],
    }
  })
  
  // ═══════════════════════════════════════════
  // 阶段 4: 建立连接 (带超时)
  // ═══════════════════════════════════════════
  const connectPromise = client.connect(transport)
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => {
      transport.close().catch(() => {})
      reject(new TelemetrySafeError('Connection timed out'))
    }, getConnectionTimeoutMs())
  })
  
  await Promise.race([connectPromise, timeoutPromise])
  
  // ═══════════════════════════════════════════
  // 阶段 5: 获取服务器能力
  // ═══════════════════════════════════════════
  const capabilities = client.getServerCapabilities()
  const serverVersion = client.getServerVersion()
  const instructions = client.getInstructions()
  
  // ═══════════════════════════════════════════
  // 阶段 6: 设置事件处理器
  // ═══════════════════════════════════════════
  client.onerror = (error: Error) => {
    // 处理连接错误...
  }
  
  client.onclose = () => {
    // 清理缓存...
    connectToServer.cache.delete(key)
    fetchToolsForClient.cache.delete(name)
    fetchResourcesForClient.cache.delete(name)
  }
  
  // ═══════════════════════════════════════════
  // 阶段 7: 返回连接结果
  // ═══════════════════════════════════════════
  return {
    name,
    client,
    type: 'connected',
    capabilities: capabilities ?? {},
    serverInfo: serverVersion,
    instructions,
    config: serverRef,
    cleanup: wrappedCleanup,
  }
}
```

### 3.3 缓存键生成

```typescript
export function getServerCacheKey(
  name: string,
  serverRef: ScopedMcpServerConfig,
): string {
  return `${name}-${jsonStringify(serverRef)}`
}
```

### 3.4 连接状态处理

```typescript
// 认证失败处理
if (error instanceof UnauthorizedError) {
  logEvent('tengu_mcp_server_needs_auth', {
    transportType: serverRef.type,
    mcpServerBaseUrl: getLoggingSafeMcpBaseUrl(serverRef),
  })
  setMcpAuthCacheEntry(name)  // 缓存需要认证状态
  return { name, type: 'needs-auth', config: serverRef }
}

// 连接失败处理
return {
  name,
  type: 'failed',
  config: serverRef,
  error: errorMessage(error),
}
```

### 3.5 重新连接机制

```typescript
export async function ensureConnectedClient(
  client: ConnectedMCPServer,
): Promise<ConnectedMCPServer> {
  // SDK 服务器在进程内运行，无需重连
  if (client.config.type === 'sdk') {
    return client
  }
  
  // 获取缓存的连接或创建新连接
  const connectedClient = await connectToServer(client.name, client.config)
  if (connectedClient.type !== 'connected') {
    throw new TelemetrySafeError(
      `MCP server "${client.name}" is not connected`,
      'MCP server not connected',
    )
  }
  return connectedClient
}
```

---

## 4. 工具注册与发现

### 4.1 MCP 工具定义

```typescript
// MCPTool.ts - 基础 MCP 工具定义
export const MCPTool = buildTool({
  isMcp: true,
  isOpenWorld() {
    return false
  },
  name: 'mcp',
  maxResultSizeChars: 100_000,
  
  async description() {
    return DESCRIPTION
  },
  
  async prompt() {
    return PROMPT
  },
  
  inputSchema: z.object({}).passthrough(),  // 接受任意输入
  
  async call() {
    return { data: '' }
  },
  
  async checkPermissions(): Promise<PermissionResult> {
    return {
      behavior: 'passthrough',
      message: 'MCPTool requires permission.',
    }
  },
  
  userFacingName: () => 'mcp',
})
```

### 4.2 工具获取与转换

```typescript
export const fetchToolsForClient = memoizeWithLRU(
  async (client: MCPServerConnection): Promise<Tool[]> => {
    if (client.type !== 'connected') return []
    
    if (!client.capabilities?.tools) {
      return []
    }
    
    // 调用 MCP 协议的 tools/list
    const result = await client.client.request(
      { method: 'tools/list' },
      ListToolsResultSchema,
    )
    
    // 清理工具数据
    const toolsToProcess = recursivelySanitizeUnicode(result.tools)
    
    // 检查是否跳过 mcp__ 前缀
    const skipPrefix =
      client.config.type === 'sdk' &&
      isEnvTruthy(process.env.CLAUDE_AGENT_SDK_MCP_NO_PREFIX)
    
    // 转换为内部 Tool 格式
    return toolsToProcess.map((tool): Tool => {
      const fullyQualifiedName = buildMcpToolName(client.name, tool.name)
      
      return {
        ...MCPTool,
        name: skipPrefix ? tool.name : fullyQualifiedName,
        mcpInfo: { serverName: client.name, toolName: tool.name },
        isMcp: true,
        
        // 从 MCP 工具注解读取特性
        searchHint: tool._meta?.['anthropic/searchHint'],
        alwaysLoad: tool._meta?.['anthropic/alwaysLoad'] === true,
        
        async description() {
          return tool.description ?? ''
        },
        
        async prompt() {
          const desc = tool.description ?? ''
          return desc.length > MAX_MCP_DESCRIPTION_LENGTH
            ? desc.slice(0, MAX_MCP_DESCRIPTION_LENGTH) + '… [truncated]'
            : desc
        },
        
        isConcurrencySafe() {
          return tool.annotations?.readOnlyHint ?? false
        },
        
        isReadOnly() {
          return tool.annotations?.readOnlyHint ?? false
        },
        
        isDestructive() {
          return tool.annotations?.destructiveHint ?? false
        },
        
        isOpenWorld() {
          return tool.annotations?.openWorldHint ?? false
        },
        
        inputJSONSchema: tool.inputSchema,
        
        // 工具调用实现
        async call(args, context, _canUseTool, parentMessage, onProgress) {
          const connectedClient = await ensureConnectedClient(client)
          const mcpResult = await callMCPToolWithUrlElicitationRetry({
            client: connectedClient,
            tool: tool.name,
            args,
            signal: context.abortController.signal,
          })
          return { data: mcpResult.content }
        },
        
        userFacingName() {
          const displayName = tool.annotations?.title || tool.name
          return `${client.name} - ${displayName} (MCP)`
        },
      }
    })
  },
  (client: MCPServerConnection) => client.name,
  MCP_FETCH_CACHE_SIZE,  // LRU 缓存大小 = 20
)
```

### 4.3 工具命名规范

```typescript
// mcpStringUtils.ts
export function buildMcpToolName(serverName: string, toolName: string): string {
  const normalizedServerName = normalizeNameForMCP(serverName)
  const normalizedToolName = normalizeNameForMCP(toolName)
  return `mcp__${normalizedServerName}__${normalizedToolName}`
}

// 示例:
// serverName: "my-server", toolName: "read_file"
// 结果: "mcp__my_server__read_file"
```

### 4.4 MCP 工具注解

MCP 工具支持以下注解:

```typescript
interface MCPToolAnnotations {
  title?: string           // 用户友好标题
  readOnlyHint?: boolean   // 只读提示
  destructiveHint?: boolean // 破坏性操作提示
  idempotentHint?: boolean  // 幂等操作提示
  openWorldHint?: boolean   // 开放世界提示
}

// 自定义 Anthropic 扩展
interface AnthropicMeta {
  'anthropic/searchHint'?: string   // 搜索提示
  'anthropic/alwaysLoad'?: boolean  // 总是加载
}
```

### 4.5 资源列表工具

```typescript
// ListMcpResourcesTool.ts
export const ListMcpResourcesTool = buildTool({
  isConcurrencySafe() {
    return true
  },
  isReadOnly() {
    return true
  },
  shouldDefer: true,  // 延迟加载
  name: LIST_MCP_RESOURCES_TOOL_NAME,
  searchHint: 'list resources from connected MCP servers',
  
  inputSchema: z.object({
    server: z.string().optional()
      .describe('Optional server name to filter resources by'),
  }),
  
  outputSchema: z.array(z.object({
    uri: z.string(),
    name: z.string(),
    mimeType: z.string().optional(),
    description: z.string().optional(),
    server: z.string(),
  })),
  
  async call(input, { options: { mcpClients } }) {
    const { server: targetServer } = input
    
    const clientsToProcess = targetServer
      ? mcpClients.filter(client => client.name === targetServer)
      : mcpClients
    
    const results = await Promise.all(
      clientsToProcess.map(async client => {
        if (client.type !== 'connected') return []
        try {
          const fresh = await ensureConnectedClient(client)
          return await fetchResourcesForClient(fresh)
        } catch (error) {
          logMCPError(client.name, errorMessage(error))
          return []
        }
      }),
    )
    
    return { data: results.flat() }
  },
})
```

---

## 5. OAuth 认证机制

### 5.1 OAuth 配置 Schema

```typescript
const McpOAuthConfigSchema = lazySchema(() =>
  z.object({
    clientId: z.string().optional(),
    callbackPort: z.number().int().positive().optional(),
    authServerMetadataUrl: z.string().url()
      .startsWith('https://').optional(),
    xaa: z.boolean().optional(),  // Cross-App Access
  }),
)

export type McpOAuthConfig = {
  clientId?: string
  callbackPort?: number
  authServerMetadataUrl?: string
  xaa?: boolean
}
```

### 5.2 ClaudeAuthProvider 实现

```typescript
export class ClaudeAuthProvider implements OAuthClientProvider {
  private serverName: string
  private serverConfig: McpSSEServerConfig | McpHTTPServerConfig
  private redirectUri: string
  private handleRedirection: boolean
  private _codeVerifier?: string
  private _authorizationUrl?: string
  private _state?: string
  private _scopes?: string
  private _metadata?: AuthorizationServerMetadata
  private _refreshInProgress?: Promise<OAuthTokens | undefined>
  private _pendingStepUpScope?: string
  
  constructor(
    serverName: string,
    serverConfig: McpSSEServerConfig | McpHTTPServerConfig,
    redirectUri: string = buildRedirectUri(),
    handleRedirection = false,
    onAuthorizationUrl?: (url: string) => void,
    skipBrowserOpen?: boolean,
  ) {
    this.serverName = serverName
    this.serverConfig = serverConfig
    this.redirectUri = redirectUri
    this.handleRedirection = handleRedirection
    this.onAuthorizationUrlCallback = onAuthorizationUrl
    this.skipBrowserOpen = skipBrowserOpen ?? false
  }
  
  // 重定向 URL
  get redirectUrl(): string {
    return this.redirectUri
  }
  
  // 客户端元数据
  get clientMetadata(): OAuthClientMetadata {
    const metadata: OAuthClientMetadata = {
      client_name: `Claude Code (${this.serverName})`,
      redirect_uris: [this.redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',  // 公共客户端
    }
    
    const metadataScope = getScopeFromMetadata(this._metadata)
    if (metadataScope) {
      metadata.scope = metadataScope
    }
    
    return metadata
  }
  
  // CIMD (Client ID Metadata Document) URL
  get clientMetadataUrl(): string | undefined {
    const override = process.env.MCP_OAUTH_CLIENT_METADATA_URL
    if (override) return override
    return MCP_CLIENT_METADATA_URL
  }
  
  // 获取客户端信息
  async clientInformation(): Promise<OAuthClientInformation | undefined> {
    const storage = getSecureStorage()
    const data = storage.read()
    const serverKey = getServerKey(this.serverName, this.serverConfig)
    
    // 优先使用存储的客户端信息
    const storedInfo = data?.mcpOAuth?.[serverKey]
    if (storedInfo?.clientId) {
      return {
        client_id: storedInfo.clientId,
        client_secret: storedInfo.clientSecret,
      }
    }
    
    // 回退到预配置的 client_id
    const configClientId = this.serverConfig.oauth?.clientId
    if (configClientId) {
      const clientConfig = data?.mcpOAuthClientConfig?.[serverKey]
      return {
        client_id: configClientId,
        client_secret: clientConfig?.clientSecret,
      }
    }
    
    return undefined  // 触发动态客户端注册
  }
  
  // 获取令牌
  async tokens(): Promise<OAuthTokens | undefined> {
    const storage = getSecureStorage()
    const data = await storage.readAsync()
    const serverKey = getServerKey(this.serverName, this.serverConfig)
    const tokenData = data?.mcpOAuth?.[serverKey]
    
    // XAA 自动刷新
    if (isXaaEnabled() && this.serverConfig.oauth?.xaa && !tokenData?.refreshToken) {
      const refreshed = await this.xaaRefresh()
      if (refreshed) return refreshed
    }
    
    if (!tokenData) return undefined
    
    const expiresIn = (tokenData.expiresAt - Date.now()) / 1000
    
    // 令牌过期且无刷新令牌
    if (expiresIn <= 0 && !tokenData.refreshToken) {
      return undefined
    }
    
    // 主动刷新即将过期的令牌
    if (expiresIn <= 300 && tokenData.refreshToken) {
      if (!this._refreshInProgress) {
        this._refreshInProgress = this.refreshAuthorization(tokenData.refreshToken)
          .finally(() => { this._refreshInProgress = undefined })
      }
      const refreshed = await this._refreshInProgress
      if (refreshed) return refreshed
    }
    
    return {
      access_token: tokenData.accessToken,
      refresh_token: tokenData.refreshToken,
      expires_in: expiresIn,
      scope: tokenData.scope,
      token_type: 'Bearer',
    }
  }
  
  // 重定向到授权 URL
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    this._authorizationUrl = authorizationUrl.toString()
    
    // 提取并存储 scope
    const scopes = authorizationUrl.searchParams.get('scope')
    if (scopes) {
      this._scopes = scopes
    }
    
    // 持久化 step-up scope
    if (this._scopes && !this.handleRedirection) {
      const storage = getSecureStorage()
      const existingData = storage.read() || {}
      const serverKey = getServerKey(this.serverName, this.serverConfig)
      const existing = existingData.mcpOAuth?.[serverKey]
      if (existing) {
        existing.stepUpScope = this._scopes
        storage.update(existingData)
      }
    }
    
    if (!this.handleRedirection) return
    
    // 验证 URL 安全性
    const urlString = authorizationUrl.toString()
    if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
      throw new Error('Invalid authorization URL: must use http:// or https://')
    }
    
    // 通知 UI 并打开浏览器
    if (this.onAuthorizationUrlCallback) {
      this.onAuthorizationUrlCallback(urlString)
    }
    
    if (!this.skipBrowserOpen) {
      await openBrowser(urlString)
    }
  }
  
  // 刷新授权
  async refreshAuthorization(
    refreshToken: string,
  ): Promise<OAuthTokens | undefined> {
    const serverKey = getServerKey(this.serverName, this.serverConfig)
    const lockfilePath = join(
      getClaudeConfigHomeDir(),
      `mcp-refresh-${serverKey.replace(/[^a-zA-Z0-9]/g, '_')}.lock`
    )
    
    // 使用锁文件防止并发刷新
    let release: (() => Promise<void>) | undefined
    try {
      release = await lockfile.lock(lockfilePath, { realpath: false })
      
      // 重新读取令牌 (可能已被其他进程刷新)
      clearKeychainCache()
      const storage = getSecureStorage()
      const data = storage.read()
      const tokenData = data?.mcpOAuth?.[serverKey]
      
      if (tokenData) {
        const expiresIn = (tokenData.expiresAt - Date.now()) / 1000
        if (expiresIn > 300) {
          return {
            access_token: tokenData.accessToken,
            refresh_token: tokenData.refreshToken,
            expires_in: expiresIn,
            scope: tokenData.scope,
            token_type: 'Bearer',
          }
        }
        if (tokenData.refreshToken) {
          refreshToken = tokenData.refreshToken
        }
      }
      
      return await this._doRefresh(refreshToken)
    } finally {
      if (release) await release()
    }
  }
}
```

### 5.3 OAuth 流程执行

```typescript
export async function performMCPOAuthFlow(
  serverName: string,
  serverConfig: McpSSEServerConfig | McpHTTPServerConfig,
  onAuthorizationUrl: (url: string) => void,
  abortSignal?: AbortSignal,
  options?: {
    skipBrowserOpen?: boolean
    onWaitingForCallback?: (submit: (callbackUrl: string) => void) => void
  },
): Promise<void> {
  // XAA 路径
  if (serverConfig.oauth?.xaa) {
    if (!isXaaEnabled()) {
      throw new Error('XAA is not enabled')
    }
    await performMCPXaaAuth(serverName, serverConfig, onAuthorizationUrl, abortSignal)
    return
  }
  
  // 获取缓存的 step-up scope
  const storage = getSecureStorage()
  const serverKey = getServerKey(serverName, serverConfig)
  const cachedEntry = storage.read()?.mcpOAuth?.[serverKey]
  const cachedStepUpScope = cachedEntry?.stepUpScope
  const cachedResourceMetadataUrl = cachedEntry?.discoveryState?.resourceMetadataUrl
  
  // 清除现有凭据
  clearServerTokensFromLocalStorage(serverName, serverConfig)
  
  // 找到可用端口
  const port = serverConfig.oauth?.callbackPort ?? (await findAvailablePort())
  const redirectUri = buildRedirectUri(port)
  
  // 创建认证提供者
  const provider = new ClaudeAuthProvider(
    serverName,
    serverConfig,
    redirectUri,
    true,  // handleRedirection
    onAuthorizationUrl,
    options?.skipBrowserOpen,
  )
  
  // 获取 OAuth 元数据
  const metadata = await fetchAuthServerMetadata(
    serverName,
    serverConfig.url,
    serverConfig.oauth?.authServerMetadataUrl,
  )
  if (metadata) {
    provider.setMetadata(metadata)
  }
  
  // 获取 OAuth state
  const oauthState = await provider.state()
  
  // 设置回调服务器
  const authorizationCode = await new Promise<string>((resolve, reject) => {
    const server = createServer((req, res) => {
      const parsedUrl = parse(req.url || '', true)
      
      if (parsedUrl.pathname === '/callback') {
        const code = parsedUrl.query.code as string
        const state = parsedUrl.query.state as string
        const error = parsedUrl.query.error
        
        if (!error && state !== oauthState) {
          res.writeHead(400)
          res.end('Invalid state parameter')
          server.close()
          reject(new Error('OAuth state mismatch'))
          return
        }
        
        if (error) {
          res.writeHead(200)
          res.end(`Authentication Error: ${error}`)
          server.close()
          reject(new Error(`OAuth error: ${error}`))
          return
        }
        
        if (code) {
          res.writeHead(200)
          res.end('Authentication Successful')
          server.close()
          resolve(code)
        }
      }
    })
    
    server.listen(port, '127.0.0.1', async () => {
      // 启动 OAuth 流程
      const result = await sdkAuth(provider, {
        serverUrl: serverConfig.url,
        scope: cachedStepUpScope,
        resourceMetadataUrl: cachedResourceMetadataUrl,
      })
    })
  })
  
  // 完成认证
  const result = await sdkAuth(provider, {
    serverUrl: serverConfig.url,
    authorizationCode,
  })
  
  if (result !== 'AUTHORIZED') {
    throw new Error('Unexpected auth result: ' + result)
  }
}
```

### 5.4 Step-Up 认证检测

```typescript
export function wrapFetchWithStepUpDetection(
  baseFetch: FetchLike,
  provider: ClaudeAuthProvider,
): FetchLike {
  return async (url, init) => {
    const response = await baseFetch(url, init)
    
    if (response.status === 403) {
      const wwwAuth = response.headers.get('WWW-Authenticate')
      if (wwwAuth?.includes('insufficient_scope')) {
        // 提取需要的 scope
        const match = wwwAuth.match(/scope=(?:"([^"]+)"|([^\s,]+))/)
        const scope = match?.[1] ?? match?.[2]
        if (scope) {
          provider.markStepUpPending(scope)
        }
      }
    }
    
    return response
  }
}
```

---

## 6. MCP 服务端实现

### 6.1 进程内服务器模式

对于特定服务器 (如 Chrome MCP, Computer Use)，Claude Code 支持进程内运行:

```typescript
// Chrome MCP 进程内服务器
if (isClaudeInChromeMCPServer(name)) {
  const { createChromeContext } = await import(
    '../../utils/claudeInChrome/mcpServer.js'
  )
  const { createClaudeForChromeMcpServer } = await import(
    '@ant/claude-for-chrome-mcp'
  )
  const { createLinkedTransportPair } = await import(
    './InProcessTransport.js'
  )
  
  const context = createChromeContext(serverRef.env)
  inProcessServer = createClaudeForChromeMcpServer(context)
  const [clientTransport, serverTransport] = createLinkedTransportPair()
  await inProcessServer.connect(serverTransport)
  transport = clientTransport
  
  logMCPDebug(name, `In-process Chrome MCP server started`)
}

// Computer Use MCP 进程内服务器
if (feature('CHICAGO_MCP') && isComputerUseMCPServer(name)) {
  const { createComputerUseMcpServerForCli } = await import(
    '../../utils/computerUse/mcpServer.js'
  )
  const { createLinkedTransportPair } = await import(
    './InProcessTransport.js'
  )
  
  inProcessServer = await createComputerUseMcpServerForCli()
  const [clientTransport, serverTransport] = createLinkedTransportPair()
  await inProcessServer.connect(serverTransport)
  transport = clientTransport
  
  logMCPDebug(name, `In-process Computer Use MCP server started`)
}
```

### 6.2 链接传输对

```typescript
// InProcessTransport.ts
export function createLinkedTransportPair(): [Transport, Transport] {
  let clientToServer: JSONRPCMessage[] = []
  let serverToClient: JSONRPCMessage[] = []
  let clientOnMessage: ((message: JSONRPCMessage) => void) | null = null
  let serverOnMessage: ((message: JSONRPCMessage) => void) | null = null
  
  const clientTransport: Transport = {
    async start() {},
    async close() {},
    async send(message: JSONRPCMessage) {
      if (serverOnMessage) {
        serverOnMessage(message)
      }
    },
    onmessage: null,
    onerror: null,
    onclose: null,
  }
  
  const serverTransport: Transport = {
    async start() {},
    async close() {},
    async send(message: JSONRPCMessage) {
      if (clientOnMessage) {
        clientOnMessage(message)
      }
    },
    onmessage: null,
    onerror: null,
    onclose: null,
  }
  
  return [clientTransport, serverTransport]
}
```

### 6.3 清理机制

```typescript
const cleanup = async () => {
  // 进程内服务器清理
  if (inProcessServer) {
    try {
      await inProcessServer.close()
    } catch (error) {
      logMCPDebug(name, `Error closing in-process server: ${error}`)
    }
    try {
      await client.close()
    } catch (error) {
      logMCPDebug(name, `Error closing client: ${error}`)
    }
    return
  }
  
  // Stdio 进程清理
  if (serverRef.type === 'stdio') {
    const stdioTransport = transport as StdioClientTransport
    const childPid = stdioTransport.pid
    
    if (childPid) {
      // 优雅关闭: SIGINT → SIGTERM → SIGKILL
      try {
        process.kill(childPid, 'SIGINT')
        await sleep(100)
        
        // 检查进程是否存在
        try {
          process.kill(childPid, 0)
          // 仍存在，尝试 SIGTERM
          process.kill(childPid, 'SIGTERM')
          await sleep(400)
          
          // 最后尝试 SIGKILL
          try {
            process.kill(childPid, 0)
            process.kill(childPid, 'SIGKILL')
          } catch {}
        } catch {}
      } catch {}
    }
  }
  
  // 关闭客户端连接
  await client.close()
}

// 注册清理回调
const cleanupUnregister = registerCleanup(cleanup)
```

---

## 7. 错误处理与重连

### 7.1 错误类型定义

```typescript
// MCP 认证错误
export class McpAuthError extends Error {
  serverName: string
  constructor(serverName: string, message: string) {
    super(message)
    this.name = 'McpAuthError'
    this.serverName = serverName
  }
}

// MCP 会话过期错误
class McpSessionExpiredError extends Error {
  constructor(serverName: string) {
    super(`MCP server "${serverName}" session expired`)
    this.name = 'McpSessionExpiredError'
  }
}

// MCP 工具调用错误
export class McpToolCallError extends TelemetrySafeError {
  constructor(
    message: string,
    telemetryMessage: string,
    readonly mcpMeta?: { _meta?: Record<string, unknown> },
  ) {
    super(message, telemetryMessage)
    this.name = 'McpToolCallError'
  }
}

// 认证取消错误
export class AuthenticationCancelledError extends Error {
  constructor() {
    super('Authentication was cancelled')
    this.name = 'AuthenticationCancelledError'
  }
}
```

### 7.2 会话过期检测

```typescript
export function isMcpSessionExpiredError(error: Error): boolean {
  const httpStatus = 'code' in error 
    ? (error as Error & { code?: number }).code 
    : undefined
    
  if (httpStatus !== 404) {
    return false
  }
  
  // 检查 JSON-RPC 错误码 -32001 (Session not found)
  return (
    error.message.includes('"code":-32001') ||
    error.message.includes('"code": -32001')
  )
}
```

### 7.3 连接错误处理

```typescript
// 增强的错误处理
client.onerror = (error: Error) => {
  const uptime = Date.now() - connectionStartTime
  hasErrorOccurred = true
  const transportType = serverRef.type || 'stdio'
  
  // 检测会话过期
  if (isMcpSessionExpiredError(error)) {
    logMCPDebug(name, `MCP session expired, triggering reconnection`)
    closeTransportAndRejectPending('session expired')
    return
  }
  
  // 远程传输的终端错误处理
  if (transportType === 'sse' || transportType === 'http') {
    // SDK 重连耗尽
    if (error.message.includes('Maximum reconnection attempts')) {
      closeTransportAndRejectPending('SSE reconnection exhausted')
      return
    }
    
    // 终端连接错误计数
    if (isTerminalConnectionError(error.message)) {
      consecutiveConnectionErrors++
      if (consecutiveConnectionErrors >= MAX_ERRORS_BEFORE_RECONNECT) {
        consecutiveConnectionErrors = 0
        closeTransportAndRejectPending('max consecutive terminal errors')
      }
    } else {
      consecutiveConnectionErrors = 0
    }
  }
}

// 终端错误检测
function isTerminalConnectionError(msg: string): boolean {
  return (
    msg.includes('ECONNRESET') ||
    msg.includes('ETIMEDOUT') ||
    msg.includes('EPIPE') ||
    msg.includes('EHOSTUNREACH') ||
    msg.includes('ECONNREFUSED') ||
    msg.includes('Body Timeout Error') ||
    msg.includes('terminated') ||
    msg.includes('SSE stream disconnected') ||
    msg.includes('Failed to reconnect SSE stream')
  )
}
```

### 7.4 关闭处理与缓存清理

```typescript
client.onclose = () => {
  const uptime = Date.now() - connectionStartTime
  const transportType = serverRef.type ?? 'unknown'
  
  logMCPDebug(
    name,
    `${transportType.toUpperCase()} connection closed after ${Math.floor(uptime / 1000)}s`,
  )
  
  // 清理所有缓存
  const key = getServerCacheKey(name, serverRef)
  fetchToolsForClient.cache.delete(name)
  fetchResourcesForClient.cache.delete(name)
  fetchCommandsForClient.cache.delete(name)
  connectToServer.cache.delete(key)
  
  logMCPDebug(name, `Cleared connection cache for reconnection`)
}
```

### 7.5 工具调用重试

```typescript
async call(args, context, ...) {
  const MAX_SESSION_RETRIES = 1
  
  for (let attempt = 0; ; attempt++) {
    try {
      const connectedClient = await ensureConnectedClient(client)
      const mcpResult = await callMCPToolWithUrlElicitationRetry({
        client: connectedClient,
        tool: tool.name,
        args,
        signal: context.abortController.signal,
      })
      
      return { data: mcpResult.content }
    } catch (error) {
      // 会话过期 - 重试
      if (error instanceof McpSessionExpiredError && attempt < MAX_SESSION_RETRIES) {
        logMCPDebug(client.name, `Retrying tool after session recovery`)
        continue
      }
      
      // 包装 MCP SDK 错误
      if (error instanceof Error && !(error instanceof TelemetrySafeError)) {
        const name = error.constructor.name
        if (name === 'Error') {
          throw new TelemetrySafeError(error.message, error.message.slice(0, 200))
        }
        if (name === 'McpError' && 'code' in error) {
          throw new TelemetrySafeError(error.message, `McpError ${error.code}`)
        }
      }
      
      throw error
    }
  }
}
```

---

## 8. 设计模式与最佳实践

### 8.1 设计模式总结

**1. 工厂模式 - 传输层创建**

```typescript
// 根据配置类型创建对应的传输层
function createTransport(config: McpServerConfig): Transport {
  switch (config.type) {
    case 'stdio':
    case undefined:
      return new StdioClientTransport(...)
    case 'sse':
      return new SSEClientTransport(...)
    case 'http':
      return new StreamableHTTPClientTransport(...)
    case 'ws':
      return new WebSocketTransport(...)
    // ...
  }
}
```

**2. Memoization 模式 - 连接缓存**

```typescript
// 使用 lodash memoize 缓存连接
export const connectToServer = memoize(
  async (name, serverRef) => { ... },
  getServerCacheKey,
)

// 带 LRU 的缓存
export const fetchToolsForClient = memoizeWithLRU(
  async (client) => { ... },
  (client) => client.name,
  MCP_FETCH_CACHE_SIZE,  // 20
)
```

**3. 策略模式 - 认证提供者**

```typescript
class ClaudeAuthProvider implements OAuthClientProvider {
  // 根据配置选择不同的认证策略
  async tokens(): Promise<OAuthTokens | undefined> {
    if (isXaaEnabled() && this.serverConfig.oauth?.xaa) {
      return this.xaaRefresh()  // XAA 策略
    }
    // 标准 OAuth 策略
    return this.standardTokens()
  }
}
```

**4. 观察者模式 - 事件处理**

```typescript
// 注册事件处理器
client.onerror = (error: Error) => { ... }
client.onclose = () => { ... }

// 清理时取消注册
stderrHandler && stdioTransport.stderr?.off('data', stderrHandler)
```

**5. 装饰器模式 - Fetch 包装**

```typescript
// 层层包装 fetch 函数
const fetch = wrapFetchWithTimeout(
  wrapFetchWithStepUpDetection(
    createFetchWithInit(),
    authProvider,
  ),
)
```

### 8.2 配置管理最佳实践

**1. 环境变量优先**

```typescript
const finalCommand = process.env.CLAUDE_CODE_SHELL_PREFIX || serverRef.command
```

**2. 安全存储敏感信息**

```typescript
// 客户端密钥存储在安全存储中
const clientConfig = getMcpClientConfig(serverName, serverConfig)
const clientSecret = clientConfig?.clientSecret
```

**3. 配置验证**

```typescript
const result = McpServerConfigSchema().safeParse(config)
if (!result.success) {
  const formattedErrors = result.error.issues
    .map(err => `${err.path.join('.')}: ${err.message}`)
    .join(', ')
  throw new Error(`Invalid configuration: ${formattedErrors}`)
}
```

### 8.3 错误处理最佳实践

**1. 分类错误处理**

```typescript
try {
  await operation()
} catch (error) {
  if (error instanceof AuthenticationCancelledError) {
    // 用户取消 - 不记录为错误
    throw error
  }
  if (error instanceof InvalidGrantError) {
    // 刷新令牌无效 - 清除并重新认证
    await this.invalidateCredentials('tokens')
    return undefined
  }
  if (error instanceof ServerError || error instanceof TemporarilyUnavailableError) {
    // 临时错误 - 重试
    await sleep(delayMs)
    continue
  }
  // 其他错误 - 向上抛出
  throw error
}
```

**2. 遥测安全错误**

```typescript
// 使用 TelemetrySafeError 包装敏感错误
throw new TelemetrySafeError_I_VERIFIED_THIS_IS_NOT_CODE_OR_FILEPATHS(
  error.message,                    // 完整消息给用户
  `McpError ${error.code}`,         // 安全消息给遥测
)
```

**3. 最佳努力清理**

```typescript
const cleanup = async () => {
  try {
    await inProcessServer.close()
  } catch {
    // 忽略清理错误
  }
  try {
    await client.close()
  } catch {
    // 忽略清理错误
  }
}
```

### 8.4 性能优化

**1. 批量连接**

```typescript
export function getMcpServerConnectionBatchSize(): number {
  return parseInt(process.env.MCP_SERVER_CONNECTION_BATCH_SIZE || '', 10) || 3
}

export function getRemoteMcpServerConnectionBatchSize(): number {
  return parseInt(process.env.MCP_REMOTE_SERVER_CONNECTION_BATCH_SIZE || '', 10) || 20
}
```

**2. 连接复用**

```typescript
// 通过 memoize 复用连接
const connectedClient = await ensureConnectedClient(client)
```

**3. 超时控制**

```typescript
// 单独的请求超时
const MCP_REQUEST_TIMEOUT_MS = 60000

// 连接超时
function getConnectionTimeoutMs(): number {
  return parseInt(process.env.MCP_TIMEOUT || '', 10) || 30000
}
```

### 8.5 安全最佳实践

**1. URL 参数脱敏**

```typescript
function redactSensitiveUrlParams(url: string): string {
  const SENSITIVE_OAUTH_PARAMS = [
    'state', 'nonce', 'code_challenge', 'code_verifier', 'code',
  ]
  try {
    const parsedUrl = new URL(url)
    for (const param of SENSITIVE_OAUTH_PARAMS) {
      if (parsedUrl.searchParams.has(param)) {
        parsedUrl.searchParams.set(param, '[REDACTED]')
      }
    }
    return parsedUrl.toString()
  } catch {
    return url
  }
}
```

**2. 状态验证**

```typescript
// 验证 OAuth state 防止 CSRF
if (state !== oauthState) {
  throw new Error('OAuth state mismatch - possible CSRF attack')
}
```

**3. URL 验证**

```typescript
if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
  throw new Error('Invalid authorization URL: must use http:// or https://')
}
```

### 8.6 配置示例

**Stdio 服务器:**

```json
{
  "mcpServers": {
    "my-local-server": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "DEBUG": "true"
      }
    }
  }
}
```

**SSE 服务器:**

```json
{
  "mcpServers": {
    "my-remote-server": {
      "type": "sse",
      "url": "https://api.example.com/mcp/sse",
      "headers": {
        "X-Custom-Header": "value"
      },
      "oauth": {
        "clientId": "my-client-id"
      }
    }
  }
}
```

**HTTP 服务器:**

```json
{
  "mcpServers": {
    "my-http-server": {
      "type": "http",
      "url": "https://api.example.com/mcp",
      "oauth": {
        "clientId": "my-client-id",
        "authServerMetadataUrl": "https://auth.example.com/.well-known/oauth-authorization-server"
      }
    }
  }
}
```

---

## 附录: 关键常量与类型

```typescript
// 工具名称
export const LIST_MCP_RESOURCES_TOOL_NAME = 'ListMcpResourcesTool'

// 超时常量
const DEFAULT_MCP_TOOL_TIMEOUT_MS = 100_000_000  // ~27.8 小时
const MCP_REQUEST_TIMEOUT_MS = 60000            // 60 秒
const AUTH_REQUEST_TIMEOUT_MS = 30000           // 30 秒
const MCP_AUTH_CACHE_TTL_MS = 15 * 60 * 1000   // 15 分钟

// 缓存大小
const MCP_FETCH_CACHE_SIZE = 20

// 错误重试
const MAX_ERRORS_BEFORE_RECONNECT = 3
const MAX_LOCK_RETRIES = 5

// 描述截断
const MAX_MCP_DESCRIPTION_LENGTH = 2048

// Accept 头
const MCP_STREAMABLE_HTTP_ACCEPT = 'application/json, text/event-stream'

// 配置作用域
type ConfigScope = 'local' | 'user' | 'project' | 'dynamic' | 'enterprise' | 'claudeai' | 'managed'

// 传输类型
type Transport = 'stdio' | 'sse' | 'sse-ide' | 'http' | 'ws' | 'ws-ide' | 'sdk'

// 服务器连接类型
type MCPServerConnection =
  | ConnectedMCPServer
  | FailedMCPServer
  | NeedsAuthMCPServer
  | PendingMCPServer
  | DisabledMCPServer
```

---

*文档版本: 1.0*
*最后更新: 2026-03-31*
*作者: Claude Code 分析系统*