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
  | { type: 'log'; data: LogEntry }
  | { type: 'tool_start'; data: ToolExecution }
  | { type: 'tool_complete'; data: { id: string; result: Record<string, unknown>; duration: number } }
  | { type: 'finding'; data: Finding }
  | { type: 'flag'; data: Flag }
  | { type: 'iteration_end'; data: { iteration: number; summary: Record<string, unknown> } }
  | { type: 'task_complete'; data: { success: boolean; flags: string[] } };