// frontend/src/components/Console/ErrorMessageView.tsx
/**
 * 错误消息视图
 */

import React from 'react';
import { AlertTriangle } from 'lucide-react';
import type { ErrorMessage } from '../../store/consoleTypes';
import { formatTime } from '../../utils/timeUtils';

export const ErrorMessageView: React.FC<{
  message: ErrorMessage;
}> = ({ message }) => (
  <div className="error-message flex gap-3 px-4 py-3 my-2 bg-red-50 border border-red-200 rounded-lg">
    {/* 图标 */}
    <div className="flex-shrink-0">
      <AlertTriangle size={20} className="text-red-500" />
    </div>

    {/* 内容 */}
    <div className="flex-1 min-w-0">
      {/* 头部 */}
      <div className="flex items-center gap-2 mb-1">
        <span className="text-sm font-medium text-red-700">Error</span>
        <span className="text-xs text-red-400">{formatTime(message.timestamp)}</span>
      </div>

      {/* 错误内容 */}
      <div className="text-sm text-red-800 whitespace-pre-wrap break-words">
        {message.content}
      </div>

      {/* 堆栈跟踪 */}
      {message.stackTrace && (
        <details className="mt-2">
          <summary className="text-xs text-red-500 cursor-pointer">Stack trace</summary>
          <pre className="mt-1 text-xs text-red-600 bg-red-100 p-2 rounded overflow-x-auto">
            {message.stackTrace}
          </pre>
        </details>
      )}
    </div>
  </div>
);

export default ErrorMessageView;