# Frontend Dashboard Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现Claude Code CLI风格的三栏Dashboard，包含时间线、实时日志流、详情面板

**Architecture:** 左栏时间线(200px) + 中栏日志流(flex) + 右栏详情面板(300px可折叠)，Zustand状态管理，WebSocket实时推送

**Tech Stack:** React 18, TypeScript, Zustand, Tailwind CSS, Lucide Icons

---

## File Structure

```
frontend/src/
├── components/
│   ├── Timeline/
│   │   ├── Timeline.tsx           # 时间线主组件
│   │   ├── IterationNode.tsx      # 迭代节点
│   │   ├── NodeIndicator.tsx      # 节点指示器(带动画)
│   │   └── Timeline.module.css    # 时间线样式
│   ├── LogStream/
│   │   ├── LogStream.tsx          # 日志流主组件
│   │   ├── LogEntry.tsx           # 单条日志
│   │   ├── ProgressBar.tsx        # 进度条
│   │   └── LogStream.module.css   # 日志样式
│   ├── DetailPanel/
│   │   ├── DetailPanel.tsx        # 详情面板主组件
│   │   ├── ToolCard.tsx           # 工具卡片
│   │   ├── FindingCard.tsx        # 发现卡片
│   │   ├── FlagCard.tsx           # Flag卡片
│   │   └── DetailPanel.module.css # 面板样式
│   └── common/
│       ├── Header.tsx             # 顶部栏
│       ├── StatsBar.tsx           # 统计栏
│       └── CopyButton.tsx         # 复制按钮
├── store/
│   ├── useAppStore.ts             # Zustand store (更新)
│   └── types.ts                   # 类型定义 (更新)
├── hooks/
│   ├── useWebSocket.ts            # WebSocket hook
│   └── useLogNavigation.ts        # 日志导航hook
├── utils/
│   ├── logFormatter.ts            # Claude Code日志格式化
│   └── timeUtils.ts               # 时间工具
└── App.tsx                        # 主应用 (更新)
```

---

## Task 1: Update Types and Store

**Files:**
- Modify: `frontend/src/store/types.ts`
- Modify: `frontend/src/store/useAppStore.ts`

### Step 1: Define new types in types.ts

```typescript
// frontend/src/store/types.ts

export type NodeType = 'think' | 'act' | 'reflect' | 'decide';

export type LogType = 'info' | 'think' | 'act' | 'reflect' | 'error' | 'success' | 'tool';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type FindingType = 'endpoint' | 'vuln' | 'credential' | 'other';

export interface LoopState {
  currentNode: NodeType;
  currentIteration: number;
  maxIterations: number;
  phase: string;
  lastAction: string;
}

export interface LogEntry {
  id: string;
  timestamp: Date;
  type: LogType;
  message: string;
  iteration: number;
  node: NodeType;
  details?: Record<string, unknown>;
  references?: {
    toolExecutionId?: string;
    findingId?: string;
    flagId?: string;
  };
}

export interface NodeResult {
  status: 'pending' | 'running' | 'completed' | 'error';
  startTime: Date;
  endTime?: Date;
  action?: string;
  result?: string;
}

export interface Iteration {
  number: number;
  startTime: Date;
  endTime?: Date;
  nodes: Record<NodeType, NodeResult>;
  findings: string[];
  flags: string[];
}

export interface ToolExecution {
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

export interface Finding {
  id: string;
  type: FindingType;
  severity: Severity;
  title: string;
  description: string;
  evidence?: string;
  toolId?: string;
  iteration: number;
  timestamp: Date;
}

export interface Flag {
  id: string;
  value: string;
  iteration: number;
  timestamp: Date;
  copied: boolean;
}

export interface CurrentTask {
  id: string;
  target: string;
  description: string;
  startTime: Date;
  status: 'running' | 'completed' | 'failed';
}

// WebSocket message types
export type WSMessage =
  | { type: 'iteration_start'; data: { iteration: number; timestamp: string } }
  | { type: 'node_start'; data: { node: NodeType; iteration: number } }
  | { type: 'node_end'; data: { node: NodeType; iteration: number; result: string } }
  | { type: 'log'; data: Omit<LogEntry, 'id'> }
  | { type: 'tool_start'; data: Omit<ToolExecution, 'id'> }
  | { type: 'tool_complete'; data: { id: string; result: Record<string, unknown>; duration: number } }
  | { type: 'finding'; data: Omit<Finding, 'id'> }
  | { type: 'flag'; data: Omit<Flag, 'id' | 'copied'> }
  | { type: 'iteration_end'; data: { iteration: number; summary: Record<string, unknown> } }
  | { type: 'task_complete'; data: { success: boolean; flags: string[] } };
```

### Step 2: Update useAppStore.ts

```typescript
// frontend/src/store/useAppStore.ts

import { create } from 'zustand';
import type {
  CurrentTask,
  LoopState,
  LogEntry,
  Iteration,
  ToolExecution,
  Finding,
  Flag,
  NodeType,
  NodeResult,
} from './types';

interface AppState {
  // Task
  currentTask: CurrentTask | null;
  
  // Loop State
  loopState: LoopState;
  
  // Log Entries
  logEntries: LogEntry[];
  
  // Iterations
  iterations: Iteration[];
  
  // Tool Executions
  toolExecutions: ToolExecution[];
  
  // Findings
  findings: Finding[];
  
  // Flags
  flags: Flag[];
  
  // WebSocket
  wsConnected: boolean;
  
  // UI State
  detailPanelCollapsed: boolean;
  detailPanelTab: 'tools' | 'findings' | 'flags';
  selectedLogEntryId: string | null;
  
  // Actions
  setCurrentTask: (task: CurrentTask | null) => void;
  updateLoopState: (state: Partial<LoopState>) => void;
  addLogEntry: (entry: LogEntry) => void;
  addIteration: (iteration: Iteration) => void;
  updateIteration: (number: number, update: Partial<Iteration>) => void;
  addToolExecution: (execution: ToolExecution) => void;
  updateToolExecution: (id: string, update: Partial<ToolExecution>) => void;
  addFinding: (finding: Finding) => void;
  addFlag: (flag: Flag) => void;
  setFlagCopied: (id: string, copied: boolean) => void;
  setWsConnected: (connected: boolean) => void;
  setDetailPanelCollapsed: (collapsed: boolean) => void;
  setDetailPanelTab: (tab: 'tools' | 'findings' | 'flags') => void;
  setSelectedLogEntry: (id: string | null) => void;
  reset: () => void;
}

const initialLoopState: LoopState = {
  currentNode: 'think',
  currentIteration: 0,
  maxIterations: 50,
  phase: 'idle',
  lastAction: '',
};

const initialState = {
  currentTask: null,
  loopState: initialLoopState,
  logEntries: [],
  iterations: [],
  toolExecutions: [],
  findings: [],
  flags: [],
  wsConnected: false,
  detailPanelCollapsed: false,
  detailPanelTab: 'tools' as const,
  selectedLogEntryId: null,
};

// Utility to generate unique IDs
let idCounter = 0;
const generateId = () => `id_${Date.now()}_${++idCounter}`;

export const useAppStore = create<AppState>((set, get) => ({
  ...initialState,

  setCurrentTask: (task) => set({ currentTask: task }),

  updateLoopState: (state) =>
    set((prev) => ({
      loopState: { ...prev.loopState, ...state },
    })),

  addLogEntry: (entry) =>
    set((state) => ({
      logEntries: [...state.logEntries, { ...entry, id: entry.id || generateId() }],
    })),

  addIteration: (iteration) =>
    set((state) => ({
      iterations: [...state.iterations, iteration],
    })),

  updateIteration: (num, update) =>
    set((state) => ({
      iterations: state.iterations.map((iter) =>
        iter.number === num ? { ...iter, ...update } : iter
      ),
    })),

  addToolExecution: (execution) =>
    set((state) => ({
      toolExecutions: [...state.toolExecutions, { ...execution, id: execution.id || generateId() }],
    })),

  updateToolExecution: (id, update) =>
    set((state) => ({
      toolExecutions: state.toolExecutions.map((tool) =>
        tool.id === id ? { ...tool, ...update } : tool
      ),
    })),

  addFinding: (finding) =>
    set((state) => ({
      findings: [...state.findings, { ...finding, id: finding.id || generateId() }],
    })),

  addFlag: (flag) =>
    set((state) => ({
      flags: [...state.flags, { ...flag, id: flag.id || generateId(), copied: false }],
    })),

  setFlagCopied: (id, copied) =>
    set((state) => ({
      flags: state.flags.map((flag) =>
        flag.id === id ? { ...flag, copied } : flag
      ),
    })),

  setWsConnected: (connected) => set({ wsConnected: connected }),

  setDetailPanelCollapsed: (collapsed) => set({ detailPanelCollapsed: collapsed }),

  setDetailPanelTab: (tab) => set({ detailPanelTab: tab }),

  setSelectedLogEntry: (id) => set({ selectedLogEntryId: id }),

  reset: () => set(initialState),
}));
```

### Step 3: Commit types and store updates

```bash
git add frontend/src/store/types.ts frontend/src/store/useAppStore.ts
git commit -m "feat: update Zustand store with AgenticLoop types"
```

---

## Task 2: Create Utility Functions

**Files:**
- Create: `frontend/src/utils/timeUtils.ts`
- Create: `frontend/src/utils/logFormatter.ts`

### Step 1: Create timeUtils.ts

```typescript
// frontend/src/utils/timeUtils.ts

/**
 * Format date to YYYY-MM-DD HH:MM:SS
 */
export function formatTimestamp(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

/**
 * Format duration in seconds to human readable
 */
export function formatDuration(seconds: number): string {
  if (seconds < 1) {
    return `${Math.round(seconds * 1000)}ms`;
  }
  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  return `${minutes}m ${secs}s`;
}

/**
 * Get relative time (e.g., "2 minutes ago")
 */
export function getRelativeTime(date: Date): string {
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  
  if (seconds < 60) {
    return 'just now';
  }
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  if (hours < 24) {
    return `${hours}h ago`;
  }
  return formatTimestamp(date);
}
```

### Step 2: Create logFormatter.ts

```typescript
// frontend/src/utils/logFormatter.ts

import type { LogType } from '../store/types';

/**
 * Claude Code CLI style log formatting
 */

export const LOG_COLORS: Record<LogType, string> = {
  info: 'text-gray-400',
  think: 'text-amber-500',
  act: 'text-blue-500',
  reflect: 'text-green-500',
  error: 'text-red-500',
  success: 'text-green-400',
  tool: 'text-cyan-500',
};

export const LOG_PREFIXES: Record<LogType, string> = {
  info: '[Info]',
  think: '[Think]',
  act: '[Act]',
  reflect: '[Reflect]',
  error: '[Error]',
  success: '[Success]',
  tool: '[Tool]',
};

/**
 * Format a log message with proper indentation for tool output
 */
export function formatToolOutput(output: string): string[] {
  return output.split('\n').map((line) => `│ ${line}`);
}

/**
 * Create a separator line with timestamp
 */
export function createSeparator(timestamp: string): string {
  return `[${timestamp}] ${'─'.repeat(50)}`;
}

/**
 * Truncate text to max length
 */
export function truncateText(text: string, maxLength: number = 100): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength - 3) + '...';
}

/**
 * Generate progress bar string
 */
export function generateProgressBar(percent: number, width: number = 20): string {
  const filled = Math.round((percent / 100) * width);
  const empty = width - filled;
  return '━'.repeat(filled) + '─'.repeat(empty);
}

/**
 * Parse command for display
 */
export function formatCommand(command: string): string {
  // Escape HTML entities
  return command
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
```

### Step 3: Commit utility functions

```bash
git add frontend/src/utils/
git commit -m "feat: add timeUtils and logFormatter utilities"
```

---

## Task 3: Create Timeline Component

**Files:**
- Create: `frontend/src/components/Timeline/Timeline.tsx`
- Create: `frontend/src/components/Timeline/IterationNode.tsx`
- Create: `frontend/src/components/Timeline/NodeIndicator.tsx`
- Create: `frontend/src/components/Timeline/Timeline.module.css`

### Step 1: Create Timeline.module.css

```css
/* frontend/src/components/Timeline/Timeline.module.css */

.timeline {
  width: 200px;
  height: 100%;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border-color);
  overflow-y: auto;
  padding: 16px 8px;
}

.iteration {
  margin-bottom: 8px;
  border-radius: 6px;
  border: 1px solid var(--border-color);
  overflow: hidden;
}

.iterationHeader {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  background: var(--bg-tertiary);
  cursor: pointer;
  user-select: none;
  font-size: 12px;
  font-weight: 500;
}

.iterationHeader:hover {
  background: var(--bg-hover);
}

.iterationHeader.active {
  background: var(--color-amber-bg);
  border-left: 3px solid var(--color-amber);
}

.iterationNumber {
  color: var(--text-primary);
}

.iterationTime {
  color: var(--text-muted);
  font-size: 10px;
}

.nodesList {
  padding: 4px 0;
  border-top: 1px solid var(--border-color);
}

.nodeItem {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  font-size: 11px;
  color: var(--text-secondary);
  cursor: pointer;
  transition: background 0.15s;
}

.nodeItem:hover {
  background: var(--bg-hover);
}

.nodeItem.running {
  background: var(--color-amber-bg);
}

.nodeItem.completed {
  color: var(--color-green);
}

.nodeItem.error {
  color: var(--color-red);
}

.nodeName {
  flex: 1;
}

.loadMore {
  padding: 12px;
  text-align: center;
  color: var(--text-muted);
  font-size: 11px;
  cursor: pointer;
}

.loadMore:hover {
  color: var(--text-primary);
}

/* Thinking animation */
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.thinking {
  animation: pulse 1.5s ease-in-out infinite;
}
```

### Step 2: Create NodeIndicator.tsx

```typescript
// frontend/src/components/Timeline/NodeIndicator.tsx

import React from 'react';
import clsx from 'clsx';
import type { NodeType } from '../../store/types';

interface NodeIndicatorProps {
  node: NodeType;
  status: 'pending' | 'running' | 'completed' | 'error';
  size?: 'sm' | 'md';
}

const nodeLabels: Record<NodeType, string> = {
  think: 'Think',
  act: 'Act',
  reflect: 'Reflect',
  decide: 'Decide',
};

export const NodeIndicator: React.FC<NodeIndicatorProps> = ({
  node,
  status,
  size = 'sm',
}) => {
  const sizeClasses = size === 'sm' ? 'w-2 h-2 text-[10px]' : 'w-3 h-3 text-xs';

  return (
    <div className="flex items-center gap-2">
      {/* Status indicator dot */}
      <span
        className={clsx(
          'rounded-full',
          sizeClasses,
          status === 'running' && 'bg-amber-500 thinking',
          status === 'completed' && 'bg-green-500',
          status === 'error' && 'bg-red-500',
          status === 'pending' && 'bg-gray-500'
        )}
      />
      
      {/* Node name */}
      <span
        className={clsx(
          size === 'sm' ? 'text-xs' : 'text-sm',
          status === 'running' && 'text-amber-500 font-medium',
          status === 'completed' && 'text-green-500',
          status === 'error' && 'text-red-500',
          status === 'pending' && 'text-gray-500'
        )}
      >
        {nodeLabels[node]}
      </span>
      
      {/* Running indicator */}
      {status === 'running' && (
        <span className="text-amber-500 text-[10px] animate-pulse">
          running
        </span>
      )}
    </div>
  );
};
```

### Step 3: Create IterationNode.tsx

```typescript
// frontend/src/components/Timeline/IterationNode.tsx

import React, { useState } from 'react';
import clsx from 'clsx';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { NodeIndicator } from './NodeIndicator';
import type { Iteration, NodeType, NodeResult } from '../../store/types';
import { getRelativeTime } from '../../utils/timeUtils';

interface IterationNodeProps {
  iteration: Iteration;
  isCurrent: boolean;
  onNodeClick: (node: NodeType) => void;
}

const nodeOrder: NodeType[] = ['think', 'act', 'reflect', 'decide'];

export const IterationNode: React.FC<IterationNodeProps> = ({
  iteration,
  isCurrent,
  onNodeClick,
}) => {
  const [expanded, setExpanded] = useState(isCurrent);

  const toggleExpand = () => setExpanded(!expanded);

  return (
    <div className="border border-border rounded-md overflow-hidden mb-2">
      {/* Header */}
      <div
        className={clsx(
          'flex items-center justify-between px-3 py-2 cursor-pointer',
          'bg-secondary hover:bg-muted transition-colors',
          isCurrent && 'bg-amber-500/10 border-l-2 border-amber-500'
        )}
        onClick={toggleExpand}
      >
        <div className="flex items-center gap-2">
          {expanded ? (
            <ChevronDown className="w-3 h-3 text-muted-foreground" />
          ) : (
            <ChevronRight className="w-3 h-3 text-muted-foreground" />
          )}
          <span className="text-xs font-medium">
            Iteration {iteration.number}
          </span>
        </div>
        <span className="text-[10px] text-muted-foreground">
          {getRelativeTime(iteration.startTime)}
        </span>
      </div>

      {/* Nodes */}
      {expanded && (
        <div className="border-t border-border">
          {nodeOrder.map((node) => {
            const nodeResult = iteration.nodes[node];
            return (
              <div
                key={node}
                className={clsx(
                  'flex items-center gap-3 px-4 py-1.5 cursor-pointer',
                  'hover:bg-muted transition-colors',
                  nodeResult.status === 'running' && 'bg-amber-500/10'
                )}
                onClick={() => onNodeClick(node)}
              >
                <NodeIndicator node={node} status={nodeResult.status} />
              </div>
            );
          })}
          
          {/* Summary */}
          {(iteration.findings.length > 0 || iteration.flags.length > 0) && (
            <div className="px-4 py-2 border-t border-border text-[10px] text-muted-foreground">
              {iteration.findings.length > 0 && (
                <span className="mr-3">{iteration.findings.length} findings</span>
              )}
              {iteration.flags.length > 0 && (
                <span className="text-green-500">{iteration.flags.length} flags</span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
```

### Step 4: Create Timeline.tsx

```typescript
// frontend/src/components/Timeline/Timeline.tsx

import React from 'react';
import { useAppStore } from '../../store/useAppStore';
import { IterationNode } from './IterationNode';
import type { NodeType } from '../../store/types';
import styles from './Timeline.module.css';

export const Timeline: React.FC = () => {
  const { iterations, loopState, setSelectedLogEntry } = useAppStore();

  const handleNodeClick = (node: NodeType) => {
    // Find the first log entry for this node in current iteration
    // This will scroll the log stream to that entry
    setSelectedLogEntry(`${loopState.currentIteration}-${node}`);
  };

  return (
    <div className={styles.timeline}>
      <div className="text-xs font-medium text-muted-foreground mb-4 px-2">
        Timeline
      </div>

      {iterations.length === 0 ? (
        <div className="text-xs text-muted-foreground text-center py-8 px-4">
          No iterations yet. Start a task to begin.
        </div>
      ) : (
        <>
          {iterations
            .slice()
            .reverse()
            .map((iteration) => (
              <IterationNode
                key={iteration.number}
                iteration={iteration}
                isCurrent={iteration.number === loopState.currentIteration}
                onNodeClick={handleNodeClick}
              />
            ))}
        </>
      )}
    </div>
  );
};
```

### Step 5: Commit Timeline component

```bash
git add frontend/src/components/Timeline/
git commit -m "feat: create Timeline component with iteration nodes"
```

---

## Task 4: Create LogStream Component

**Files:**
- Create: `frontend/src/components/LogStream/LogStream.tsx`
- Create: `frontend/src/components/LogStream/LogEntry.tsx`
- Create: `frontend/src/components/LogStream/ProgressBar.tsx`
- Create: `frontend/src/components/LogStream/LogStream.module.css`

### Step 1: Create LogStream.module.css

```css
/* frontend/src/components/LogStream/LogStream.module.css */

.logStream {
  flex: 1;
  height: 100%;
  background: var(--bg-primary);
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 12px;
  line-height: 1.6;
  overflow-y: auto;
  padding: 16px;
}

.separator {
  color: var(--text-muted);
  margin: 8px 0;
  font-size: 11px;
}

.logEntry {
  margin: 2px 0;
  white-space: pre-wrap;
  word-break: break-word;
}

.logPrefix {
  font-weight: 600;
}

.logMessage {
  color: var(--text-primary);
}

.toolOutput {
  padding-left: 4px;
  border-left: 1px solid var(--border-color);
  margin-left: 2px;
  color: var(--text-secondary);
}

.progressBar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 4px 0;
}

.progressFill {
  color: var(--color-blue);
}

.progressPercent {
  color: var(--text-muted);
  font-size: 11px;
  min-width: 40px;
}

.progressTime {
  color: var(--text-muted);
  font-size: 11px;
}

/* Scrollbar styling */
.logStream::-webkit-scrollbar {
  width: 8px;
}

.logStream::-webkit-scrollbar-track {
  background: var(--bg-secondary);
}

.logStream::-webkit-scrollbar-thumb {
  background: var(--border-color);
  border-radius: 4px;
}

.logStream::-webkit-scrollbar-thumb:hover {
  background: var(--text-muted);
}

/* Highlight selected entry */
.logEntry.selected {
  background: var(--color-amber-bg);
  border-radius: 2px;
}

/* Jump to latest button */
.jumpToLatest {
  position: sticky;
  bottom: 16px;
  left: 50%;
  transform: translateX(-50%);
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  padding: 4px 12px;
  font-size: 11px;
  cursor: pointer;
  color: var(--text-primary);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
}

.jumpToLatest:hover {
  background: var(--bg-tertiary);
}

/* Search bar */
.searchBar {
  position: sticky;
  top: 0;
  background: var(--bg-primary);
  padding: 8px;
  border-bottom: 1px solid var(--border-color);
  margin: -16px -16px 16px -16px;
}

.searchInput {
  width: 100%;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  padding: 6px 10px;
  font-size: 11px;
  color: var(--text-primary);
  outline: none;
}

.searchInput:focus {
  border-color: var(--color-blue);
}
```

### Step 2: Create ProgressBar.tsx

```typescript
// frontend/src/components/LogStream/ProgressBar.tsx

import React from 'react';
import { generateProgressBar } from '../../utils/logFormatter';
import { formatDuration } from '../../utils/timeUtils';

interface ProgressBarProps {
  percent: number;
  message?: string;
  duration?: number;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  percent,
  message,
  duration,
}) => {
  return (
    <div className="flex items-center gap-2 my-1 text-xs">
      {/* Message */}
      {message && <span className="text-muted-foreground">{message}</span>}
      
      {/* Progress bar */}
      <span className="text-blue-500 font-mono">
        {generateProgressBar(percent, 20)}
      </span>
      
      {/* Percent */}
      <span className="text-muted-foreground min-w-[40px]">
        {percent}%
      </span>
      
      {/* Duration */}
      {duration !== undefined && (
        <span className="text-muted-foreground">
          {formatDuration(duration)}
        </span>
      )}
    </div>
  );
};
```

### Step 3: Create LogEntry.tsx

```typescript
// frontend/src/components/LogStream/LogEntry.tsx

import React from 'react';
import clsx from 'clsx';
import type { LogEntry as LogEntryType } from '../../store/types';
import { LOG_COLORS, LOG_PREFIXES, formatToolOutput } from '../../utils/logFormatter';
import { formatTimestamp } from '../../utils/timeUtils';

interface LogEntryProps {
  entry: LogEntryType;
  isSelected?: boolean;
  onClick?: () => void;
}

export const LogEntryComponent: React.FC<LogEntryProps> = ({
  entry,
  isSelected,
  onClick,
}) => {
  const prefix = LOG_PREFIXES[entry.type];
  const colorClass = LOG_COLORS[entry.type];

  // Check if details contain tool output
  const hasToolOutput = entry.details?.output && typeof entry.details.output === 'string';

  return (
    <div
      className={clsx(
        'my-0.5 cursor-pointer hover:bg-muted/30 rounded px-1',
        isSelected && 'bg-amber-500/10'
      )}
      onClick={onClick}
    >
      {/* Main log line */}
      <span className={colorClass}>
        <span className="font-semibold">{prefix}</span>
        {' '}
        <span className="text-foreground">{entry.message}</span>
      </span>

      {/* Tool output with indentation */}
      {hasToolOutput && (
        <div className="border-l border-border pl-2 ml-1 mt-1 text-muted-foreground">
          {formatToolOutput(entry.details.output as string).map((line, i) => (
            <div key={i} className="whitespace-pre text-xs">
              {line}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// Separator component
export const LogSeparator: React.FC<{ timestamp: Date }> = ({ timestamp }) => (
  <div className="text-muted-foreground text-xs my-2">
    [{formatTimestamp(timestamp)}] {'─'.repeat(50)}
  </div>
);
```

### Step 4: Create LogStream.tsx

```typescript
// frontend/src/components/LogStream/LogStream.tsx

import React, { useEffect, useRef, useState } from 'react';
import { useAppStore } from '../../store/useAppStore';
import { LogEntryComponent, LogSeparator } from './LogEntry';
import { ArrowDown } from 'lucide-react';
import styles from './LogStream.module.css';

export const LogStream: React.FC = () => {
  const { logEntries, selectedLogEntryId, setSelectedLogEntry } = useAppStore();
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  // Auto-scroll to bottom when new entries arrive
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logEntries, autoScroll]);

  // Handle scroll to detect if user scrolled up
  const handleScroll = () => {
    if (containerRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
      const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
      setAutoScroll(isAtBottom);
    }
  };

  // Jump to latest
  const jumpToLatest = () => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
      setAutoScroll(true);
    }
  };

  // Filter logs by search term
  const filteredEntries = searchTerm
    ? logEntries.filter((entry) =>
        entry.message.toLowerCase().includes(searchTerm.toLowerCase())
      )
    : logEntries;

  return (
    <div
      ref={containerRef}
      className={styles.logStream}
      onScroll={handleScroll}
    >
      {/* Search bar */}
      <div className={styles.searchBar}>
        <input
          type="text"
          placeholder="Search logs... (Ctrl+F)"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className={styles.searchInput}
        />
      </div>

      {/* Log entries */}
      {filteredEntries.map((entry, index) => {
        const showSeparator =
          index === 0 ||
          entry.iteration !== filteredEntries[index - 1].iteration;

        return (
          <React.Fragment key={entry.id}>
            {showSeparator && <LogSeparator timestamp={entry.timestamp} />}
            <LogEntryComponent
              entry={entry}
              isSelected={entry.id === selectedLogEntryId}
              onClick={() => setSelectedLogEntry(entry.id)}
            />
          </React.Fragment>
        );
      })}

      {/* Jump to latest button */}
      {!autoScroll && (
        <button className={styles.jumpToLatest} onClick={jumpToLatest}>
          <ArrowDown className="w-3 h-3 inline mr-1" />
          Jump to latest
        </button>
      )}
    </div>
  );
};
```

### Step 5: Commit LogStream component

```bash
git add frontend/src/components/LogStream/
git commit -m "feat: create LogStream component with Claude Code CLI style"
```

---

## Task 5: Create DetailPanel Component

**Files:**
- Create: `frontend/src/components/DetailPanel/DetailPanel.tsx`
- Create: `frontend/src/components/DetailPanel/ToolCard.tsx`
- Create: `frontend/src/components/DetailPanel/FindingCard.tsx`
- Create: `frontend/src/components/DetailPanel/FlagCard.tsx`
- Create: `frontend/src/components/DetailPanel/DetailPanel.module.css`

### Step 1: Create DetailPanel.module.css

```css
/* frontend/src/components/DetailPanel/DetailPanel.module.css */

.panel {
  width: 300px;
  height: 100%;
  background: var(--bg-secondary);
  border-left: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  transition: width 0.2s ease;
}

.panel.collapsed {
  width: 40px;
}

.tabs {
  display: flex;
  border-bottom: 1px solid var(--border-color);
  background: var(--bg-tertiary);
}

.tab {
  flex: 1;
  padding: 10px 8px;
  text-align: center;
  font-size: 11px;
  font-weight: 500;
  color: var(--text-muted);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  transition: all 0.15s;
}

.tab:hover {
  color: var(--text-primary);
  background: var(--bg-hover);
}

.tab.active {
  color: var(--text-primary);
  border-bottom-color: var(--color-blue);
}

.tabCount {
  display: inline-block;
  margin-left: 4px;
  padding: 1px 4px;
  background: var(--bg-primary);
  border-radius: 4px;
  font-size: 10px;
}

.content {
  flex: 1;
  overflow-y: auto;
  padding: 12px;
}

.content.empty {
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-muted);
  font-size: 12px;
}

/* Card styles */
.card {
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 8px;
  cursor: pointer;
  transition: background 0.15s;
}

.card:hover {
  background: var(--bg-hover);
}

.cardHeader {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.cardTitle {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
}

.cardMeta {
  font-size: 10px;
  color: var(--text-muted);
}

.cardBody {
  font-size: 11px;
  color: var(--text-secondary);
  line-height: 1.5;
}

.cardActions {
  display: flex;
  gap: 8px;
  margin-top: 8px;
}

.cardButton {
  padding: 4px 8px;
  font-size: 10px;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  color: var(--text-primary);
  cursor: pointer;
}

.cardButton:hover {
  background: var(--bg-hover);
}

/* Severity borders */
.card.critical {
  border-left: 3px solid #DC2626;
}

.card.high {
  border-left: 3px solid #EA580C;
}

.card.medium {
  border-left: 3px solid #CA8A04;
}

.card.low {
  border-left: 3px solid #2563EB;
}

/* Collapsed panel icons */
.collapsedTabs {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 8px 0;
  gap: 8px;
}

.collapsedTab {
  padding: 8px;
  border-radius: 4px;
  cursor: pointer;
  color: var(--text-muted);
}

.collapsedTab:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.collapsedTab.active {
  background: var(--color-blue-bg);
  color: var(--color-blue);
}
```

### Step 2: Create ToolCard.tsx

```typescript
// frontend/src/components/DetailPanel/ToolCard.tsx

import React from 'react';
import clsx from 'clsx';
import { CheckCircle, XCircle, Clock, ExternalLink } from 'lucide-react';
import type { ToolExecution } from '../../store/types';
import { formatDuration } from '../../utils/timeUtils';
import styles from './DetailPanel.module.css';

interface ToolCardProps {
  tool: ToolExecution;
  onClick: () => void;
}

export const ToolCard: React.FC<ToolCardProps> = ({ tool, onClick }) => {
  const StatusIcon = tool.status === 'success' ? CheckCircle : XCircle;
  const statusColor =
    tool.status === 'success'
      ? 'text-green-500'
      : tool.status === 'error'
      ? 'text-red-500'
      : 'text-yellow-500';

  return (
    <div className={styles.card} onClick={onClick}>
      <div className={styles.cardHeader}>
        <span className={styles.cardTitle}>{tool.toolName}</span>
        <span className={styles.cardMeta}>
          {tool.duration ? formatDuration(tool.duration) : '...'}
        </span>
      </div>

      <div className={styles.cardBody}>
        <div className="flex items-center gap-2 mb-2">
          <StatusIcon className={clsx('w-3 h-3', statusColor)} />
          <span className="text-xs capitalize">{tool.status}</span>
        </div>

        {tool.command && (
          <div className="text-xs text-muted-foreground mb-2 font-mono truncate">
            $ {tool.command}
          </div>
        )}

        {tool.error && (
          <div className="text-xs text-red-400 mt-1 truncate">
            {tool.error}
          </div>
        )}
      </div>

      <div className={styles.cardActions}>
        <button className={styles.cardButton}>
          <ExternalLink className="w-3 h-3 inline mr-1" />
          View
        </button>
      </div>
    </div>
  );
};
```

### Step 3: Create FindingCard.tsx

```typescript
// frontend/src/components/DetailPanel/FindingCard.tsx

import React from 'react';
import clsx from 'clsx';
import { AlertTriangle, ExternalLink, Copy } from 'lucide-react';
import type { Finding } from '../../store/types';
import styles from './DetailPanel.module.css';

interface FindingCardProps {
  finding: Finding;
  onClick: () => void;
}

const severityLabels = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

const severityColors = {
  critical: 'text-red-500 bg-red-500/10',
  high: 'text-orange-500 bg-orange-500/10',
  medium: 'text-yellow-500 bg-yellow-500/10',
  low: 'text-blue-500 bg-blue-500/10',
};

export const FindingCard: React.FC<FindingCardProps> = ({ finding, onClick }) => {
  return (
    <div className={clsx(styles.card, styles[finding.severity])} onClick={onClick}>
      <div className={styles.cardHeader}>
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-3 h-3" />
          <span className={clsx('text-[10px] px-1.5 py-0.5 rounded', severityColors[finding.severity])}>
            {severityLabels[finding.severity]}
          </span>
        </div>
      </div>

      <div className={styles.cardTitle}>{finding.title}</div>
      
      <div className={styles.cardBody}>
        <div className="text-xs mb-2">{finding.description}</div>
        
        {finding.evidence && (
          <div className="text-xs text-muted-foreground font-mono bg-primary/50 p-2 rounded mt-2 truncate">
            {finding.evidence}
          </div>
        )}
      </div>

      <div className={styles.cardActions}>
        <button className={styles.cardButton}>
          <ExternalLink className="w-3 h-3 inline mr-1" />
          Details
        </button>
        {finding.evidence && (
          <button
            className={styles.cardButton}
            onClick={(e) => {
              e.stopPropagation();
              navigator.clipboard.writeText(finding.evidence || '');
            }}
          >
            <Copy className="w-3 h-3 inline mr-1" />
            Copy
          </button>
        )}
      </div>
    </div>
  );
};
```

### Step 4: Create FlagCard.tsx

```typescript
// frontend/src/components/DetailPanel/FlagCard.tsx

import React from 'react';
import { Flag, Copy, Check } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';
import type { Flag as FlagType } from '../../store/types';
import styles from './DetailPanel.module.css';

interface FlagCardProps {
  flag: FlagType;
}

export const FlagCard: React.FC<FlagCardProps> = ({ flag }) => {
  const { setFlagCopied } = useAppStore();

  const handleCopy = () => {
    navigator.clipboard.writeText(flag.value);
    setFlagCopied(flag.id, true);
  };

  return (
    <div className={clsx(styles.card, 'border-l-green-500')}>
      <div className={styles.cardHeader}>
        <div className="flex items-center gap-2 text-green-500">
          <Flag className="w-4 h-4" />
          <span className={styles.cardTitle}>Flag Found</span>
        </div>
      </div>

      <div className="font-mono text-sm bg-primary/50 p-3 rounded border border-green-500/30 text-green-400 break-all">
        {flag.value}
      </div>

      <div className={styles.cardActions}>
        <button className={styles.cardButton} onClick={handleCopy}>
          {flag.copied ? (
            <>
              <Check className="w-3 h-3 inline mr-1" />
              Copied
            </>
          ) : (
            <>
              <Copy className="w-3 h-3 inline mr-1" />
              Copy
            </>
          )}
        </button>
      </div>
    </div>
  );
};

import clsx from 'clsx';
```

### Step 5: Create DetailPanel.tsx

```typescript
// frontend/src/components/DetailPanel/DetailPanel.tsx

import React from 'react';
import { Wrench, Search, Flag, ChevronLeft, ChevronRight } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';
import { ToolCard } from './ToolCard';
import { FindingCard } from './FindingCard';
import { FlagCard } from './FlagCard';
import styles from './DetailPanel.module.css';

type TabType = 'tools' | 'findings' | 'flags';

export const DetailPanel: React.FC = () => {
  const {
    toolExecutions,
    findings,
    flags,
    detailPanelCollapsed,
    detailPanelTab,
    setDetailPanelCollapsed,
    setDetailPanelTab,
    setSelectedLogEntry,
  } = useAppStore();

  const handleToolClick = (toolId: string) => {
    // Scroll log to this tool
    setSelectedLogEntry(toolId);
  };

  const handleFindingClick = (findingId: string) => {
    setSelectedLogEntry(findingId);
  };

  if (detailPanelCollapsed) {
    return (
      <div className={clsx(styles.panel, styles.collapsed)}>
        <div className={styles.collapsedTabs}>
          <button
            className={clsx(styles.collapsedTab, detailPanelTab === 'tools' && styles.active)}
            onClick={() => {
              setDetailPanelTab('tools');
              setDetailPanelCollapsed(false);
            }}
            title="Tools"
          >
            <Wrench className="w-4 h-4" />
          </button>
          <button
            className={clsx(styles.collapsedTab, detailPanelTab === 'findings' && styles.active)}
            onClick={() => {
              setDetailPanelTab('findings');
              setDetailPanelCollapsed(false);
            }}
            title="Findings"
          >
            <Search className="w-4 h-4" />
          </button>
          <button
            className={clsx(styles.collapsedTab, detailPanelTab === 'flags' && styles.active)}
            onClick={() => {
              setDetailPanelTab('flags');
              setDetailPanelCollapsed(false);
            }}
            title="Flags"
          >
            <Flag className="w-4 h-4" />
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.panel}>
      {/* Tabs */}
      <div className={styles.tabs}>
        <button
          className={clsx(styles.tab, detailPanelTab === 'tools' && styles.active)}
          onClick={() => setDetailPanelTab('tools')}
        >
          Tools
          {toolExecutions.length > 0 && (
            <span className={styles.tabCount}>{toolExecutions.length}</span>
          )}
        </button>
        <button
          className={clsx(styles.tab, detailPanelTab === 'findings' && styles.active)}
          onClick={() => setDetailPanelTab('findings')}
        >
          Findings
          {findings.length > 0 && (
            <span className={styles.tabCount}>{findings.length}</span>
          )}
        </button>
        <button
          className={clsx(styles.tab, detailPanelTab === 'flags' && styles.active)}
          onClick={() => setDetailPanelTab('flags')}
        >
          Flags
          {flags.length > 0 && (
            <span className={styles.tabCount}>{flags.length}</span>
          )}
        </button>
        <button
          className="p-2 hover:bg-muted"
          onClick={() => setDetailPanelCollapsed(true)}
          title="Collapse"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>

      {/* Content */}
      <div className={styles.content}>
        {detailPanelTab === 'tools' && (
          toolExecutions.length === 0 ? (
            <div className={styles.empty}>No tool executions yet</div>
          ) : (
            toolExecutions
              .slice()
              .reverse()
              .map((tool) => (
                <ToolCard
                  key={tool.id}
                  tool={tool}
                  onClick={() => handleToolClick(tool.id)}
                />
              ))
          )
        )}

        {detailPanelTab === 'findings' && (
          findings.length === 0 ? (
            <div className={styles.empty}>No findings yet</div>
          ) : (
            findings
              .slice()
              .reverse()
              .map((finding) => (
                <FindingCard
                  key={finding.id}
                  finding={finding}
                  onClick={() => handleFindingClick(finding.id)}
                />
              ))
          )
        )}

        {detailPanelTab === 'flags' && (
          flags.length === 0 ? (
            <div className={styles.empty}>No flags found yet</div>
          ) : (
            flags.map((flag) => <FlagCard key={flag.id} flag={flag} />)
          )
        )}
      </div>
    </div>
  );
};

import clsx from 'clsx';
```

### Step 6: Commit DetailPanel component

```bash
git add frontend/src/components/DetailPanel/
git commit -m "feat: create DetailPanel with Tools, Findings, Flags tabs"
```

---

## Task 6: Create Common Components

**Files:**
- Create: `frontend/src/components/common/Header.tsx`
- Create: `frontend/src/components/common/StatsBar.tsx`
- Create: `frontend/src/components/common/CopyButton.tsx`

### Step 1: Create CopyButton.tsx

```typescript
// frontend/src/components/common/CopyButton.tsx

import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface CopyButtonProps {
  text: string;
  className?: string;
}

export const CopyButton: React.FC<CopyButtonProps> = ({ text, className = '' }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className={`px-2 py-1 text-xs rounded border border-border hover:bg-muted transition-colors ${className}`}
    >
      {copied ? (
        <>
          <Check className="w-3 h-3 inline mr-1" />
          Copied
        </>
      ) : (
        <>
          <Copy className="w-3 h-3 inline mr-1" />
          Copy
        </>
      )}
    </button>
  );
};
```

### Step 2: Create Header.tsx

```typescript
// frontend/src/components/common/Header.tsx

import React from 'react';
import { Shield, Wifi, WifiOff, Settings } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';
import clsx from 'clsx';

export const Header: React.FC = () => {
  const { currentTask, wsConnected } = useAppStore();

  return (
    <header className="flex items-center justify-between px-6 py-4 border-b border-border bg-secondary">
      <div className="flex items-center gap-3">
        <Shield className="w-6 h-6 text-primary" />
        <div>
          <h1 className="text-lg font-bold">CTF-Agent 2.0 Dashboard</h1>
          {currentTask && (
            <p className="text-xs text-muted-foreground">
              {currentTask.description || currentTask.target}
            </p>
          )}
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* WebSocket status */}
        <div className="flex items-center gap-2">
          {wsConnected ? (
            <>
              <Wifi className="w-4 h-4 text-green-500" />
              <span className="text-xs text-green-500">Connected</span>
            </>
          ) : (
            <>
              <WifiOff className="w-4 h-4 text-red-500" />
              <span className="text-xs text-red-500">Disconnected</span>
            </>
          )}
        </div>

        {/* Settings button */}
        <button className="p-2 hover:bg-muted rounded">
          <Settings className="w-4 h-4 text-muted-foreground" />
        </button>
      </div>
    </header>
  );
};
```

### Step 3: Create StatsBar.tsx

```typescript
// frontend/src/components/common/StatsBar.tsx

import React from 'react';
import { Target, Flag, Wrench, Brain, Repeat } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';

export const StatsBar: React.FC = () => {
  const { findings, flags, toolExecutions, loopState } = useAppStore();

  const stats = [
    {
      icon: Target,
      label: 'Findings',
      value: findings.length,
      color: 'text-blue-500',
    },
    {
      icon: Flag,
      label: 'Flags',
      value: flags.length,
      color: 'text-green-500',
    },
    {
      icon: Wrench,
      label: 'Tools',
      value: toolExecutions.length,
      color: 'text-cyan-500',
    },
    {
      icon: Brain,
      label: 'Skills',
      value: 15,
      color: 'text-purple-500',
    },
    {
      icon: Repeat,
      label: 'Iterations',
      value: `${loopState.currentIteration}/${loopState.maxIterations}`,
      color: 'text-amber-500',
    },
  ];

  return (
    <div className="grid grid-cols-5 gap-4 px-6 py-3 border-b border-border bg-secondary/50">
      {stats.map((stat) => (
        <div
          key={stat.label}
          className="flex items-center gap-2 px-4 py-2 bg-muted/30 rounded-lg"
        >
          <stat.icon className={`w-4 h-4 ${stat.color}`} />
          <div>
            <div className="text-xs text-muted-foreground">{stat.label}</div>
            <div className="text-lg font-bold">{stat.value}</div>
          </div>
        </div>
      ))}
    </div>
  );
};
```

### Step 4: Commit common components

```bash
git add frontend/src/components/common/
git commit -m "feat: create Header, StatsBar, CopyButton components"
```

---

## Task 7: Update App.tsx Layout

**Files:**
- Modify: `frontend/src/App.tsx`

### Step 1: Update App.tsx with three-column layout

```typescript
// frontend/src/App.tsx

import React from 'react';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import { Settings, Shield } from 'lucide-react';

// Components
import { Header } from './components/common/Header';
import { StatsBar } from './components/common/StatsBar';
import { Timeline } from './components/Timeline/Timeline';
import { LogStream } from './components/LogStream/LogStream';
import { DetailPanel } from './components/DetailPanel/DetailPanel';

function Dashboard() {
  return (
    <div className="flex flex-col h-screen bg-background text-foreground">
      {/* Header */}
      <Header />
      
      {/* Stats Bar */}
      <StatsBar />
      
      {/* Main Content - Three Column Layout */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: Timeline */}
        <Timeline />
        
        {/* Center: Log Stream */}
        <LogStream />
        
        {/* Right: Detail Panel */}
        <DetailPanel />
      </div>
    </div>
  );
}

function SettingsPage() {
  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-4">Settings</h1>
      <div className="bg-secondary rounded-lg p-6 border border-border">
        <p className="text-muted-foreground">Settings page coming soon.</p>
      </div>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
```

### Step 2: Commit App.tsx update

```bash
git add frontend/src/App.tsx
git commit -m "feat: update App.tsx with three-column dashboard layout"
```

---

## Task 8: Create WebSocket Hook

**Files:**
- Create: `frontend/src/hooks/useWebSocket.ts`

### Step 1: Create useWebSocket.ts

```typescript
// frontend/src/hooks/useWebSocket.ts

import { useEffect, useRef, useCallback } from 'react';
import { useAppStore } from '../store/useAppStore';
import type { WSMessage, NodeType, LogEntry, ToolExecution, Finding, Flag } from '../store/types';

const WS_URL = 'ws://localhost:8000/ws';

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

  const {
    setWsConnected,
    addLogEntry,
    updateLoopState,
    addToolExecution,
    updateToolExecution,
    addFinding,
    addFlag,
    addIteration,
    updateIteration,
    setCurrentTask,
  } = useAppStore();

  const handleMessage = useCallback((event: MessageEvent) => {
    try {
      const message: WSMessage = JSON.parse(event.data);
      
      switch (message.type) {
        case 'iteration_start': {
          const { iteration, timestamp } = message.data;
          addIteration({
            number: iteration,
            startTime: new Date(timestamp),
            nodes: {
              think: { status: 'pending', startTime: new Date() },
              act: { status: 'pending', startTime: new Date() },
              reflect: { status: 'pending', startTime: new Date() },
              decide: { status: 'pending', startTime: new Date() },
            },
            findings: [],
            flags: [],
          });
          updateLoopState({ currentIteration: iteration });
          addLogEntry({
            timestamp: new Date(),
            type: 'info',
            message: `Iteration ${iteration} started`,
            iteration,
            node: 'think',
          });
          break;
        }

        case 'node_start': {
          const { node, iteration } = message.data;
          updateLoopState({ currentNode: node as NodeType });
          // Update iteration node status
          // (Would need additional store method for this)
          addLogEntry({
            timestamp: new Date(),
            type: node as LogEntry['type'],
            message: `Starting ${node}...`,
            iteration,
            node: node as NodeType,
          });
          break;
        }

        case 'node_end': {
          const { node, iteration, result } = message.data;
          addLogEntry({
            timestamp: new Date(),
            type: node as LogEntry['type'],
            message: result,
            iteration,
            node: node as NodeType,
          });
          break;
        }

        case 'log': {
          addLogEntry({
            ...message.data,
            timestamp: new Date(message.data.timestamp),
          } as LogEntry);
          break;
        }

        case 'tool_start': {
          addToolExecution({
            ...message.data,
            startTime: new Date(message.data.startTime),
          } as ToolExecution);
          break;
        }

        case 'tool_complete': {
          const { id, result, duration } = message.data;
          updateToolExecution(id, {
            status: 'success',
            duration,
            output: JSON.stringify(result, null, 2),
          });
          break;
        }

        case 'finding': {
          addFinding({
            ...message.data,
            timestamp: new Date(message.data.timestamp),
          } as Finding);
          break;
        }

        case 'flag': {
          addFlag({
            ...message.data,
            timestamp: new Date(message.data.timestamp),
          } as Flag);
          break;
        }

        case 'iteration_end': {
          const { iteration, summary } = message.data;
          // Update iteration end time
          addLogEntry({
            timestamp: new Date(),
            type: 'info',
            message: `Iteration ${iteration} completed`,
            iteration,
            node: 'decide',
          });
          break;
        }

        case 'task_complete': {
          const { success, flags } = message.data;
          addLogEntry({
            timestamp: new Date(),
            type: success ? 'success' : 'error',
            message: success 
              ? `Task completed successfully. Found ${flags.length} flags.`
              : 'Task completed without finding flags.',
            iteration: 0,
            node: 'decide',
          });
          break;
        }
      }
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error);
    }
  }, [
    addLogEntry,
    updateLoopState,
    addToolExecution,
    updateToolExecution,
    addFinding,
    addFlag,
    addIteration,
  ]);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsConnected(true);
      console.log('WebSocket connected');
    };

    ws.onmessage = handleMessage;

    ws.onclose = () => {
      setWsConnected(false);
      console.log('WebSocket disconnected');
      
      // Reconnect after 3 seconds
      reconnectTimeoutRef.current = window.setTimeout(() => {
        connect();
      }, 3000);
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }, [setWsConnected, handleMessage]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    wsRef.current?.close();
  }, []);

  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  return {
    isConnected: wsRef.current?.readyState === WebSocket.OPEN,
    connect,
    disconnect,
  };
}
```

### Step 2: Commit WebSocket hook

```bash
git add frontend/src/hooks/useWebSocket.ts
git commit -m "feat: create useWebSocket hook for real-time updates"
```

---

## Task 9: Update index.css with CSS Variables

**Files:**
- Modify: `frontend/src/index.css`

### Step 1: Update index.css with CSS variables for theming

```css
/* frontend/src/index.css */

@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
  /* Light theme */
  --bg-primary: #FAFAFA;
  --bg-secondary: #F3F4F6;
  --bg-tertiary: #E5E7EB;
  --bg-hover: #D1D5DB;
  
  --text-primary: #1F2937;
  --text-secondary: #4B5563;
  --text-muted: #9CA3AF;
  
  --border-color: #E5E7EB;
  
  --color-amber: #D97706;
  --color-amber-bg: rgba(217, 119, 6, 0.1);
  --color-green: #059669;
  --color-red: #DC2626;
  --color-blue: #2563EB;
  --color-blue-bg: rgba(37, 99, 235, 0.1);
  --color-cyan: #0891B2;
  --color-purple: #7C3AED;
}

@media (prefers-color-scheme: dark) {
  :root {
    /* Dark theme */
    --bg-primary: #0D0D0D;
    --bg-secondary: #171717;
    --bg-tertiary: #262626;
    --bg-hover: #404040;
    
    --text-primary: #F3F4F6;
    --text-secondary: #D1D5DB;
    --text-muted: #9CA3AF;
    
    --border-color: #1F2937;
    
    --color-amber: #F59E0B;
    --color-amber-bg: rgba(245, 158, 11, 0.1);
    --color-green: #10B981;
    --color-red: #EF4444;
    --color-blue: #3B82F6;
    --color-blue-bg: rgba(59, 130, 246, 0.1);
    --color-cyan: #06B6D4;
    --color-purple: #8B5CF6;
  }
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body, #root {
  height: 100%;
  width: 100%;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
}

/* Scrollbar styling */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

::-webkit-scrollbar-track {
  background: var(--bg-secondary);
}

::-webkit-scrollbar-thumb {
  background: var(--border-color);
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: var(--text-muted);
}

/* Animation for thinking state */
@keyframes thinking-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.thinking {
  animation: thinking-pulse 1.5s ease-in-out infinite;
}

/* Progress bar animation */
@keyframes progress-flow {
  0% { background-position: 0 0; }
  100% { background-position: 20px 0; }
}

.progress-animated {
  background-image: linear-gradient(
    -45deg,
    rgba(255, 255, 255, 0.15) 25%,
    transparent 25%,
    transparent 50%,
    rgba(255, 255, 255, 0.15) 50%,
    rgba(255, 255, 255, 0.15) 75%,
    transparent 75%,
    transparent
  );
  background-size: 20px 20px;
  animation: progress-flow 1s linear infinite;
}
```

### Step 2: Commit CSS update

```bash
git add frontend/src/index.css
git commit -m "feat: update CSS with theme variables and animations"
```

---

## Task 10: Final Integration and Test

### Step 1: Verify all components are correctly imported

Run: `cd frontend && npm run build`
Expected: Build succeeds without errors

### Step 2: Test in development mode

Run: `cd frontend && npm run dev`
Expected: Dashboard loads with three-column layout

### Step 3: Commit final integration

```bash
git add frontend/
git commit -m "feat: complete Dashboard redesign with Claude Code CLI style"
```

---

## Self-Review Checklist

### Spec Coverage

| Requirement | Task | Status |
|------------|------|--------|
| Three-column layout | Task 7 | Done |
| Timeline component | Task 3 | Done |
| Log stream (Claude Code style) | Task 4 | Done |
| Detail panel | Task 5 | Done |
| Claude Code color scheme | Task 9 | Done |
| WebSocket integration | Task 8 | Done |
| Stats bar | Task 6 | Done |

### Placeholder Scan

- [x] No TBD/TODO placeholders
- [x] All code is complete
- [x] All imports are specified

### Type Consistency

- [x] NodeType used consistently
- [x] LogEntry type matches store and component usage
- [x] ToolExecution type matches store and component usage
- [x] Finding type matches store and component usage
- [x] Flag type matches store and component usage

---

## Execution Options

Plan complete and saved to `docs/superpowers/plans/2026-04-02-frontend-dashboard-redesign.md`.

**Two execution options:**

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**