// frontend/src/components/Console/AssistantMessageView.tsx
/**
 * AI消息视图 - Markdown渲染
 */

import React from 'react';
import { Bot } from 'lucide-react';
import type { AssistantMessage } from '../../store/consoleTypes';
import { formatTime } from '../../utils/timeUtils';
import { MarkdownRenderer } from './MarkdownRenderer';

export const AssistantMessageView: React.FC<{
  message: AssistantMessage;
}> = ({ message }) => (
  <div className="assistant-message flex gap-3 px-4 py-3 my-2">
    {/* 头像 */}
    <div className="flex-shrink-0 w-6 h-6 rounded-full bg-green-500 flex items-center justify-center">
      <Bot size={14} className="text-white" />
    </div>

    {/* 内容 */}
    <div className="flex-1 min-w-0">
      {/* 头部 */}
      <div className="flex items-center gap-2 mb-1">
        <span className="text-sm font-medium text-gray-800">Assistant</span>
        <span className="text-xs text-gray-400">{formatTime(message.timestamp)}</span>
        {message.isStreaming && (
          <span className="text-xs text-blue-500 flex items-center gap-1">
            <span className="pulse-dot-blue w-1.5 h-1.5"></span>
            streaming...
          </span>
        )}
      </div>

      {/* Markdown内容 */}
      <div className="text-sm text-gray-700 prose prose-sm max-w-none">
        <MarkdownRenderer content={message.content} />
        {message.isStreaming && <span className="streaming-cursor"></span>}
      </div>
    </div>
  </div>
);

export default AssistantMessageView;