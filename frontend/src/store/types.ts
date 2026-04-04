// frontend/src/store/types.ts

export type NodeType = 'think' | 'act' | 'reflect' | 'decide';

export type LogType = 'info' | 'think' | 'act' | 'reflect' | 'error' | 'success' | 'tool' | 'warning';

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

// Chat types
export interface Attachment {
  id: string;
  name: string;
  size: number;
  type: string;
  file: File;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'system';
  content: string;
  attachments?: Attachment[];
  timestamp: Date;
}

export interface ChatState {
  inputValue: string;
  attachments: Attachment[];
  isDragging: boolean;
  isExecuting: boolean;
  messages: ChatMessage[];
}

// WebSocket message types
export type WSMessage =
  // 基础事件（后端实际发送）
  | { type: 'assistant_message'; content?: string; turn?: number }
  | { type: 'tool_result'; tool_name?: string }
  | { type: 'complete'; reason?: string }
  | { type: 'loop_detected'; tool?: string }
  | { type: 'status'; status?: string; target?: string }
  | { type: 'error'; message?: string }
  // 其他事件
  | { type: 'connection_established'; data: { message: string; timestamp: string } }
  | { type: 'task_start'; data: { target: string; description?: string; timestamp: string } }
  | { type: 'iteration_start'; data: { iteration: number; timestamp: string } }
  | { type: 'node_start'; data: { node: NodeType; iteration: number } }
  | { type: 'node_end'; data: { node: NodeType; iteration: number; result: string } }
  | { type: 'log'; data: LogEntry }
  | { type: 'tool_start'; data: ToolExecution }
  | { type: 'tool_complete'; data: { id: string; result: Record<string, unknown>; duration: number } }
  | { type: 'finding'; data: Finding }
  | { type: 'flag'; data: Flag }
  | { type: 'iteration_end'; data: { iteration: number; summary: Record<string, unknown> } }
  | { type: 'task_complete'; data: { success: boolean; flags: string[] } }
  // Chat message types
  | { type: 'user_input'; data: { message: string; attachments: Omit<Attachment, 'file'>[] } }
  | { type: 'interrupt'; data: { reason: string } }
  | { type: 'file_uploaded'; data: { fileId: string; filename: string; size: number } }
  | { type: 'execution_status'; data: { isExecuting: boolean; task?: string } };