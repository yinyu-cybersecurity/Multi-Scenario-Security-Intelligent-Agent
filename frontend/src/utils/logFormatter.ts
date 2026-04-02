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