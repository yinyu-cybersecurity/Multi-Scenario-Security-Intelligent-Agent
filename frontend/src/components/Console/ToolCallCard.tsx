// frontend/src/components/Console/ToolCallCard.tsx
/**
 * 工具调用卡片 - 完全复刻Claude Code视觉效果
 *
 * 特性:
 * - 脉冲动画（运行中状态）
 * - 折叠展开（Ctrl+O）
 * - 命令预览
 * - 输出/错误显示
 */

import React, { useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Terminal,
  FileText,
  Search,
  FolderSearch,
  Globe,
  Database,
  Shield,
  Zap,
  CheckCircle,
  XCircle,
  Loader2,
  ChevronDown,
  LucideIcon,
} from 'lucide-react';
import type { ToolCallMessage } from '../../store/consoleTypes';
import '../../styles/animations.css';

/**
 * 工具图标映射
 */
const TOOL_ICON_MAP: Record<string, LucideIcon> = {
  'Bash': Terminal,
  'Read': FileText,
  'Write': FileText,
  'Edit': FileText,
  'Glob': FolderSearch,
  'Grep': Search,
  'WebFetch': Globe,
  'WebSearch': Search,
  'LSP': FileText,
  'httpx': Globe,
  'nuclei': Shield,
  'sqlmap': Database,
  'ffuf': Zap,
  'fscan': Shield,
  'subfinder': Globe,
  'gobuster': FolderSearch,
};

/**
 * 状态图标组件
 */
const StatusIcon: React.FC<{ status: ToolCallMessage['status'] }> = ({ status }) => {
  if (status === 'running') {
    return <Loader2 size={16} className="spin text-blue-500" />;
  }
  if (status === 'completed') {
    return <CheckCircle size={16} className="text-green-500" />;
  }
  if (status === 'error') {
    return <XCircle size={16} className="text-red-500" />;
  }
  return null;
};

/**
 * 格式化时长
 */
function formatDuration(duration?: number): string {
  if (!duration) return '';
  if (duration < 1) return `${(duration * 1000).toFixed(0)}ms`;
  return `${duration.toFixed(1)}s`;
}

/**
 * 截断输出
 */
function truncateOutput(output: string, maxLength = 1000): string {
  if (output.length <= maxLength) return output;
  return output.slice(0, maxLength) + '\n... (output truncated)';
}

/**
 * 工具调用卡片组件
 */
export const ToolCallCard: React.FC<{
  message: ToolCallMessage;
  onToggle: () => void;
}> = ({ message, onToggle }) => {
  // 键盘快捷键 Ctrl+O
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.ctrlKey && e.key === 'o') {
      e.preventDefault();
      onToggle();
    }
  }, [onToggle]);

  // 获取工具图标
  const IconComponent = TOOL_ICON_MAP[message.toolName] || Terminal;

  // 状态类名
  const statusClass = message.status === 'running'
    ? 'tool-running pulse-border-blue'
    : message.status === 'completed'
      ? 'tool-completed border-green-500'
      : 'tool-error border-red-500';

  return (
    <motion.div
      className={`tool-call-card rounded-lg border bg-white overflow-hidden my-2 ${statusClass}`}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      onKeyDown={handleKeyDown}
      tabIndex={0}
    >
      {/* 卡片头部 */}
      <div
        className="tool-call-header flex justify-between items-center px-4 py-3 cursor-pointer bg-gray-50 hover:bg-gray-100 transition-colors"
        onClick={onToggle}
      >
        <div className="flex items-center gap-2">
          {/* 状态图标 */}
          <StatusIcon status={message.status} />

          {/* 工具图标 */}
          <IconComponent size={16} className="text-gray-600" />

          {/* 工具名称 */}
          <span className="font-semibold text-gray-800">{message.toolName}</span>

          {/* 状态文本 */}
          <span className="text-sm text-gray-500">
            {message.status === 'running' ? (
              <span className="text-blue-500">(running...)</span>
            ) : message.status === 'completed' ? (
              <span className="text-green-600">(completed {formatDuration(message.duration)})</span>
            ) : (
              <span className="text-red-500">(error)</span>
            )}
          </span>

          {/* 脉冲指示器 - 运行时显示 */}
          {message.status === 'running' && (
            <span className="pulse-dot-blue ml-1"></span>
          )}
        </div>

        <div className="flex items-center gap-2 text-gray-400">
          {/* 展开提示 */}
          <span className="text-xs opacity-0 hover:opacity-100 transition-opacity">(ctrl+o)</span>

          {/* 展开箭头 */}
          <motion.div animate={{ rotate: message.isExpanded ? 180 : 0 }}>
            <ChevronDown size={14} />
          </motion.div>
        </div>
      </div>

      {/* 命令预览 - 始终显示 */}
      {message.command && (
        <div className="px-4 py-2 bg-gray-900 border-t border-gray-700">
          <pre className="text-sm text-gray-100 font-mono whitespace-pre-wrap break-words m-0">
            {message.command}
          </pre>
        </div>
      )}

      {/* 详情区域 - 可折叠 */}
      <AnimatePresence>
        {message.isExpanded && (message.output || message.error) && (
          <motion.div
            className="tool-call-details overflow-hidden"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            {/* 输出内容 */}
            {message.output && (
              <div className="px-4 py-3 bg-gray-50 border-t">
                <div className="text-xs text-gray-500 mb-1 font-medium">Output:</div>
                <pre className="text-sm text-green-800 bg-green-50 p-3 rounded font-mono whitespace-pre-wrap break-words m-0 max-h-96 overflow-auto">
                  {truncateOutput(message.output)}
                </pre>
              </div>
            )}

            {/* 错误内容 */}
            {message.error && (
              <div className="px-4 py-3 bg-red-50 border-t border-red-200">
                <div className="text-xs text-red-600 mb-1 font-medium">Error:</div>
                <pre className="text-sm text-red-700 bg-red-100 p-3 rounded font-mono whitespace-pre-wrap break-words m-0">
                  {message.error}
                </pre>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* 运行中指示器 */}
      {message.status === 'running' && !message.isExpanded && (
        <div className="px-4 py-2 bg-gray-50 border-t">
          <span className="text-gray-400 text-sm animate-pulse">Executing...</span>
        </div>
      )}
    </motion.div>
  );
};

export default ToolCallCard;