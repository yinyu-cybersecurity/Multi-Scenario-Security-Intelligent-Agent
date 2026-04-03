// frontend/src/store/consoleTypes.ts
/**
 * 控制台消息类型系统 - 完全复刻Claude Code
 */

import type { Attachment } from './types';

/**
 * 消息类型
 */
export type ConsoleMessageType =
  | 'user'           // 用户输入
  | 'assistant'      // AI响应
  | 'tool_call'      // 工具调用卡片
  | 'error'          // 错误消息
  | 'separator'      // 迭代分隔线
  | 'system';        // 系统消息

/**
 * 工具调用状态
 */
export type ToolCallStatus = 'running' | 'completed' | 'error';

/**
 * 控制台消息基类
 */
export interface ConsoleMessageBase {
  id: string;
  type: ConsoleMessageType;
  timestamp: Date;
  iteration: number;
}

/**
 * 用户消息
 */
export interface UserMessage extends ConsoleMessageBase {
  type: 'user';
  content: string;
  attachments?: Attachment[];
}

/**
 * AI消息 - 支持Markdown
 */
export interface AssistantMessage extends ConsoleMessageBase {
  type: 'assistant';
  content: string;         // Markdown内容
  isStreaming?: boolean;   // 是否正在流式输出
}

/**
 * 工具调用消息 - 核心卡片类型
 */
export interface ToolCallMessage extends ConsoleMessageBase {
  type: 'tool_call';
  toolName: string;        // 工具名称: Bash, Read, Glob, Grep, httpx...
  command?: string;        // 命令内容
  description?: string;    // 描述文本
  status: ToolCallStatus;
  startTime: Date;
  endTime?: Date;
  duration?: number;       // 执行时长(秒)
  output?: string;         // 输出内容
  error?: string;          // 错误信息
  isExpanded: boolean;     // 是否展开详情
}

/**
 * 错误消息
 */
export interface ErrorMessage extends ConsoleMessageBase {
  type: 'error';
  content: string;
  stackTrace?: string;
}

/**
 * 迭代分隔线
 */
export interface SeparatorMessage extends ConsoleMessageBase {
  type: 'separator';
  iterationNumber: number;
}

/**
 * 系统消息
 */
export interface SystemMessage extends ConsoleMessageBase {
  type: 'system';
  content: string;
}

/**
 * 统一消息类型
 */
export type ConsoleMessage =
  | UserMessage
  | AssistantMessage
  | ToolCallMessage
  | ErrorMessage
  | SeparatorMessage
  | SystemMessage;

/**
 * 工具图标映射
 */
export const TOOL_ICONS: Record<string, string> = {
  'Bash': 'terminal',
  'Read': 'file-text',
  'Write': 'file-plus',
  'Edit': 'edit',
  'Glob': 'folder-search',
  'Grep': 'search',
  'WebFetch': 'globe',
  'WebSearch': 'search',
  'LSP': 'code',
  'Task': 'list-todo',
  'TodoWrite': 'check-square',
  'httpx': 'globe',
  'nuclei': 'shield',
  'sqlmap': 'database',
  'ffuf': 'zap',
  'fscan': 'scan',
  'subfinder': 'globe',
  'gobuster': 'folder-search',
};

/**
 * 工具颜色映射
 */
export const TOOL_COLORS: Record<string, string> = {
  'Bash': '#6b7280',       // 灰色
  'Read': '#3b82f6',       // 蓝色
  'Write': '#10b981',      // 绿色
  'Edit': '#f59e0b',       // 橙色
  'Glob': '#8b5cf6',       // 紫色
  'Grep': '#ec4899',       // 粉色
  'WebFetch': '#06b6d4',   // 青色
  'WebSearch': '#06b6d4',
  'httpx': '#3b82f6',
  'nuclei': '#ef4444',     // 红色
  'sqlmap': '#f59e0b',
  'ffuf': '#8b5cf6',
  'fscan': '#ef4444',
};

/**
 * 获取工具图标
 */
export function getToolIcon(toolName: string): string {
  // 处理工具变体名称
  const baseName = toolName.split('_')[0].split('-')[0];
  return TOOL_ICONS[baseName] || TOOL_ICONS[toolName] || 'terminal';
}

/**
 * 获取工具颜色
 */
export function getToolColor(toolName: string): string {
  const baseName = toolName.split('_')[0].split('-')[0];
  return TOOL_COLORS[baseName] || TOOL_COLORS[toolName] || '#6b7280';
}