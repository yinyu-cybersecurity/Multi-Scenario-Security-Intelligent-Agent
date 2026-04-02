# CTF-Agent 2.0 Frontend Dashboard Redesign Design

> **Goal**: 优化前端Dashboard，提高展示性和观测性，完全学习Claude Code CLI风格

> **Design Date**: 2026-04-02

---

## Overview

重新设计CTF-Agent 2.0前端Dashboard，实现专业监控仪表板风格。核心改进：

1. **三栏分栏布局** - 时间线、实时日志、详情面板
2. **Claude Code CLI风格日志** - 终端风格输出、语法高亮、进度条
3. **垂直时间线视图** - 展示迭代历史，支持折叠展开
4. **上下文关联** - 日志引用工具执行，点击可跳转
5. **专业配色** - 深色主题，Claude Code配色方案

---

## Layout Architecture

### Overall Structure

```
+------------------------------------------------------------------+
|  Header: CTF-Agent 2.0 Dashboard          [Status] [Settings]    |
+------------------------------------------------------------------+
|  Stats Bar: [Findings: 12] [Flags: 1] [Tools: 5] [Iter: 15/50]  |
+----------+--------------------------------+----------------------+
|          |                                |                      |
| Timeline |      Real-time Log Stream      |   Detail Panel       |
|  (200px) |         (flex-grow)            |      (300px)         |
|          |                                |      [collapsible]   |
+----------+--------------------------------+----------------------+
```

### Column Specifications

| Column | Width | Purpose | Key Features |
|--------|-------|---------|--------------|
| Timeline | 200px fixed | 迭代历史 | 垂直时间线，可折叠，点击跳转 |
| Log Stream | flex-grow | 实时日志 | 终端风格，语法高亮，自动滚动 |
| Detail Panel | 300px, collapsible | 工具/发现详情 | 标签切换，引用关联 |

---

## Color Scheme (Claude Code Style)

### Light Theme

| Element | Color | Usage |
|---------|-------|-------|
| Background | `#FAFAFA` | 主背景 |
| Text Primary | `#1F2937` | 主要文字 |
| Text Secondary | `#6B7280` | 次要文字 |
| Border | `#E5E7EB` | 分隔线 |
| Active Node | `#D97706` | 琥珀色，活跃状态 |
| Success | `#059669` | 绿色，成功/完成 |
| Error | `#DC2626` | 红色，错误/失败 |
| Info | `#2563EB` | 蓝色，信息/执行 |
| Warning | `#CA8A04` | 黄色，警告 |

### Dark Theme

| Element | Color | Usage |
|---------|-------|-------|
| Background | `#0D0D0D` | 主背景 |
| Text Primary | `#F3F4F6` | 主要文字 |
| Text Secondary | `#9CA3AF` | 次要文字 |
| Border | `#1F2937` | 分隔线 |
| Active Node | `#D97706` | 琥珀色，活跃状态 |
| Success | `#10B981` | 绿色 |
| Error | `#EF4444` | 红色 |
| Info | `#3B82F6` | 蓝色 |

---

## Component Design

### 1. Timeline Component

#### Visual Structure

```
Timeline (左栏 200px)
├── [Current Iteration]  ◀ 高亮背景
│   ├── ● Think   ──────  活跃脉冲动画
│   ├── ○ Act
│   ├── ○ Reflect
│   └── ○ Decide
│
├── [Iteration 14]  ────  可点击折叠
│   ├── ✓ Think
│   ├── ✓ Act
│   ├── ✓ Reflect
│   └── ✓ Decide
│
├── [Iteration 13]
│   └── ...
│
└── [Load More]
```

#### Node States

| State | Icon | Color | Animation |
|-------|------|-------|-----------|
| Pending | `○` | Gray | None |
| Running | `●` | Amber | Pulse animation |
| Completed | `✓` | Green | None |
| Error | `✕` | Red | None |

#### Thinking Animation (Claude Code Style)

```css
@keyframes thinking-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.thinking-indicator {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #D97706;
  animation: thinking-pulse 1.5s ease-in-out infinite;
}
```

#### Interactions

1. **Click Iteration**: Log area scrolls to corresponding position
2. **Click Node**: Highlight log entries for that node
3. **Collapse/Expand**: Control iteration detail display
4. **Auto-scroll**: Automatically scroll to current iteration

---

### 2. Log Stream Component

#### Claude Code CLI Log Format

```
[2026-04-02 10:23:45] ───────────────────────────────────────
> Iteration 15 started

[Think]
Analyzing current state...
Available tools: nmap, nuclei, sqlmap
Memory: 3 findings loaded
Decision: Run nmap scan

[Act]
Running: nmap -sV target.example.com
│ scanning... ━━━━━━━━━━━━ 100% 2.3s
│ PORT    STATE SERVICE
│ 80/tcp  open  http
│ 443/tcp open  https
Tool completed in 2.3s

[Reflect]
Extracted 2 endpoints from results
Updated memory with findings
No flags detected

[Decide]
Continue to next iteration (Reason: No flag found)

[2026-04-02 10:23:51] ───────────────────────────────────────
> Iteration 16 started
...
```

#### Log Entry Types

| Type | Prefix | Color | Example |
|------|--------|-------|---------|
| Info | `[Info]` | Default | `[Info] Starting scan` |
| Think | `[Think]` | Amber `#D97706` | `[Think] Analyzing...` |
| Act | `[Act]` | Blue `#2563EB` | `[Act] Running nmap` |
| Reflect | `[Reflect]` | Green `#059669` | `[Reflect] Found 2 issues` |
| Error | `[Error]` | Red `#DC2626` | `[Error] Connection failed` |
| Success | `[Success]` | Green `#059669` | `[Success] Flag found` |
| Tool | `[Tool]` | Cyan `#0891B2` | `[Tool] nmap completed` |

#### Progress Bar Style

```
│ scanning... ━━━━━━━━━━━━ 100% 2.3s
```

- Use Unicode `━` characters
- Show percentage and duration
- Animate fill from left to right

#### Loading Animation

```
Thinking... ◐
Thinking... ◑
Thinking... ◒
Thinking... ◓
```

- Claude Code style rotation animation
- Use ◐ ◑ ◒ ◓ characters
- Or use pulse dots `● ○`

#### Error Highlighting

```
[Error] Tool execution failed
│ Error: Connection refused
│ Target: 192.168.1.1
│ Port: 80
Retrying with fallback...
```

#### Flag Discovery

```
[Flag Found]
flag{example_flag_12345}
Copied to clipboard
```

#### Interactions

1. **Auto-scroll**: New logs auto-scroll to bottom
2. **Pause on scroll**: Pause auto-scroll when user scrolls up
3. **Jump to latest**: Button to jump to newest logs
4. **Search filter**: `Ctrl+F` to search, filter by node type
5. **Cross-reference**: Click tool reference to jump to detail

---

### 3. Detail Panel Component

#### Panel Structure

```
Detail Panel (右栏 300px, 可折叠)
├── [Tools] [Findings] [Flags]  ← 标签切换
│
├── Tools Tab
│   ┌─────────────────────────────┐
│   │ nmap                    2.3s│
│   │ Status: Success             │
│   │ Target: target.example.com  │
│   └─────────────────────────────┘
│
├── Findings Tab
│   ┌─────────────────────────────┐
│   │ [Endpoint] /admin           │
│   │ Severity: Medium            │
│   └─────────────────────────────┘
│
└── Flags Tab
    ┌─────────────────────────────┐
    │ flag{example_flag_12345}    │
    │ [Copy] [Export All]         │
    └─────────────────────────────┘
```

#### Tool Execution Card

```
┌─────────────────────────────────────┐
│ nmap                           2.3s │
├─────────────────────────────────────┤
│ Status: Success                     │
│ Target: target.example.com          │
│ Ports: 80, 443                      │
│ Started: 10:23:45                   │
│                                      │
│ [View Output] [Copy Command]        │
└─────────────────────────────────────┘
```

#### Finding Card (Severity Color-coded)

```
┌─────────────────────────────────────┐
│ [Critical] SQL Injection            │ ← Red border
├─────────────────────────────────────┤
│ Location: /api/users?id=            │
│ Parameter: id                       │
│ Payload: ' OR 1=1--                 │
│ Tool: sqlmap                        │
│ Time: 2026-04-02 10:24:12           │
│                                      │
│ [View Details] [Copy Payload]       │
└─────────────────────────────────────┘
```

**Severity Colors**:
- Critical: `#DC2626` (Red)
- High: `#EA580C` (Orange)
- Medium: `#CA8A04` (Yellow)
- Low: `#2563EB` (Blue)

#### Panel Collapse/Expand

```
Expanded (300px):
├─────────────┤
│   Details   │
│     ...     │
└─────────────┘

Collapsed (40px):
├── [D] [T] [F] [S] ──┤
    ↑   ↑   ↑   ↑
   Details Tools Findings Settings
```

#### Real-time Updates

- Tools automatically added when execution completes
- Findings appended with fade-in animation
- Flags highlighted with flash animation

---

## State Management

### Store Structure

```typescript
interface AppState {
  // Task Info
  currentTask: {
    id: string;
    target: string;
    description: string;
    startTime: Date;
    status: 'running' | 'completed' | 'failed';
  } | null;

  // Loop State
  loopState: {
    currentNode: 'think' | 'act' | 'reflect' | 'decide';
    currentIteration: number;
    maxIterations: number;
    phase: string;
    lastAction: string;
  };

  // Log Entries
  logEntries: LogEntry[];
  
  // Iteration History
  iterations: Iteration[];

  // Tool Executions
  toolExecutions: ToolExecution[];

  // Findings
  findings: Finding[];

  // Flags
  flags: Flag[];

  // WebSocket
  wsConnected: boolean;
}

interface LogEntry {
  id: string;
  timestamp: Date;
  type: 'info' | 'think' | 'act' | 'reflect' | 'error' | 'success';
  message: string;
  iteration: number;
  node: string;
  details?: object;
  references?: {
    toolExecutionId?: string;
    findingId?: string;
    flagId?: string;
  };
}

interface Iteration {
  number: number;
  startTime: Date;
  endTime?: Date;
  nodes: {
    think: NodeResult;
    act: NodeResult;
    reflect: NodeResult;
    decide: NodeResult;
  };
  findings: string[];
  flags: string[];
}

interface NodeResult {
  status: 'pending' | 'running' | 'completed' | 'error';
  startTime: Date;
  endTime?: Date;
  action?: string;
  result?: string;
}

interface ToolExecution {
  id: string;
  toolName: string;
  command?: string;
  startTime: Date;
  endTime?: Date;
  duration?: number;
  status: 'pending' | 'running' | 'success' | 'error';
  output?: string;
  error?: string;
  iteration: number;
}

interface Finding {
  id: string;
  type: 'endpoint' | 'vuln' | 'credential' | 'other';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  evidence?: string;
  toolId?: string;
  iteration: number;
  timestamp: Date;
}

interface Flag {
  id: string;
  value: string;
  iteration: number;
  timestamp: Date;
  copied: boolean;
}
```

---

## WebSocket Communication

### Message Types

```typescript
type WSMessage = 
  | { type: 'iteration_start'; data: { iteration: number; timestamp: Date } }
  | { type: 'node_start'; data: { node: string; iteration: number } }
  | { type: 'node_end'; data: { node: string; iteration: number; result: string } }
  | { type: 'log'; data: LogEntry }
  | { type: 'tool_start'; data: ToolExecution }
  | { type: 'tool_complete'; data: { id: string; result: object; duration: number } }
  | { type: 'finding'; data: Finding }
  | { type: 'flag'; data: Flag }
  | { type: 'iteration_end'; data: { iteration: number; summary: object } }
  | { type: 'task_complete'; data: { success: boolean; flags: string[] } };
```

### Data Flow

```
Backend (Python)              Frontend (React)
      │                            │
      │  WebSocket Server          │
      │  (FastAPI)                 │
      │                            │
      ├──── WS Message ───────────►│
      │                            │
      │                     ┌──────┴──────┐
      │                     │   Zustand   │
      │                     │    Store    │
      │                     └──────┬──────┘
      │                            │
      │              ┌─────────────┼─────────────┐
      │              │             │             │
      │         ┌────▼────┐  ┌────▼────┐  ┌────▼────┐
      │         │Timeline │  │  Log    │  │ Detail  │
      │         │Component│  │Component│  │ Panel   │
      │         └─────────┘  └─────────┘  └─────────┘
```

---

## Technical Implementation

### Key Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| react-window | ^1.8.x | Virtual scrolling for log entries |
| zustand | ^4.5.x | State management |
| lucide-react | ^0.x | Icons |
| tailwindcss | ^3.4.x | Styling |
| clsx | ^2.1.x | Conditional classes |

### Performance Optimizations

1. **Virtual Scrolling**: Use react-window for log entries (handle 1000+ entries)
2. **Log Deduplication**: Merge identical consecutive logs with count
3. **Reference Jumping**: Use ID-based linking between components
4. **Real-time Updates**: WebSocket push instead of polling

### Accessibility

1. **Keyboard Navigation**: Arrow keys for timeline, Tab for panel
2. **Screen Reader**: ARIA labels for all interactive elements
3. **High Contrast**: Support prefers-contrast media query
4. **Reduced Motion**: Support prefers-reduced-motion

---

## File Structure

```
frontend/src/
├── components/
│   ├── Timeline/
│   │   ├── Timeline.tsx           # Main timeline component
│   │   ├── IterationNode.tsx      # Iteration node component
│   │   ├── NodeIndicator.tsx      # Node indicator with animation
│   │   └── Timeline.module.css    # Timeline styles
│   ├── LogStream/
│   │   ├── LogStream.tsx          # Main log stream component
│   │   ├── LogEntry.tsx           # Individual log entry
│   │   ├── LogFilter.tsx          # Log filter controls
│   │   ├── ProgressBar.tsx        # Progress bar component
│   │   └── LogStream.module.css   # Log styles
│   ├── DetailPanel/
│   │   ├── DetailPanel.tsx        # Main detail panel
│   │   ├── ToolCard.tsx           # Tool execution card
│   │   ├── FindingCard.tsx        # Finding card
│   │   ├── FlagCard.tsx           # Flag card
│   │   └── DetailPanel.module.css # Panel styles
│   └── common/
│       ├── Header.tsx             # Dashboard header
│       ├── StatsBar.tsx           # Statistics bar
│       └── CopyButton.tsx         # Copy to clipboard button
├── store/
│   ├── useAppStore.ts             # Main store (updated)
│   └── types.ts                   # Type definitions
├── hooks/
│   ├── useWebSocket.ts            # WebSocket hook
│   └── useLogNavigation.ts        # Log navigation hook
├── utils/
│   ├── logFormatter.ts            # Claude Code log formatting
│   └── timeUtils.ts               # Time utilities
└── App.tsx                        # Main app (updated)
```

---

## Implementation Priority

### Phase 1: Core Components (High Priority)

1. Update Zustand store with new types
2. Implement Timeline component
3. Implement LogStream component with Claude Code styling
4. Implement DetailPanel component

### Phase 2: Integration (Medium Priority)

1. Update WebSocket message handling
2. Implement cross-component navigation
3. Add keyboard shortcuts
4. Add search/filter functionality

### Phase 3: Polish (Lower Priority)

1. Add animations and transitions
2. Add accessibility features
3. Performance optimization
4. Dark/light theme toggle

---

## Success Criteria

1. **Observability**: Users can track agent progress in real-time
2. **Navigability**: Users can jump between related log entries and details
3. **Performance**: Dashboard handles 1000+ log entries without lag
4. **Usability**: Interface is intuitive for penetration testers
5. **Consistency**: Design matches Claude Code CLI aesthetic

---

## Design Checklist

- [x] Layout architecture defined
- [x] Color scheme specified (Claude Code style)
- [x] Timeline component design complete
- [x] Log stream format specified (Claude Code CLI style)
- [x] Detail panel design complete
- [x] State management structure defined
- [x] WebSocket message types defined
- [x] File structure planned
- [x] Implementation priority set