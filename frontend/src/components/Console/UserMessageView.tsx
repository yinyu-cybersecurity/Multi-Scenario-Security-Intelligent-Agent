// frontend/src/components/Console/UserMessageView.tsx
/**
 * 用户消息视图 - 简单文本显示
 */

import React from 'react';
import { User } from 'lucide-react';
import type { UserMessage } from '../../store/consoleTypes';
import { formatTime } from '../../utils/timeUtils';

export const UserMessageView: React.FC<{
  message: UserMessage;
}> = ({ message }) => (
  <div className="user-message flex gap-3 px-4 py-3 my-2">
    {/* 头像 */}
    <div className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500 flex items-center justify-center">
      <User size={14} className="text-white" />
    </div>

    {/* 内容 */}
    <div className="flex-1 min-w-0">
      {/* 头部 */}
      <div className="flex items-center gap-2 mb-1">
        <span className="text-sm font-medium text-gray-800">User</span>
        <span className="text-xs text-gray-400">{formatTime(message.timestamp)}</span>
      </div>

      {/* 消息内容 */}
      <div className="text-sm text-gray-700 whitespace-pre-wrap break-words">
        {message.content}
      </div>

      {/* 附件 */}
      {message.attachments && message.attachments.length > 0 && (
        <div className="flex flex-wrap gap-2 mt-2">
          {message.attachments.map(att => (
            <span
              key={att.id}
              className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded"
            >
              📎 {att.name} ({(att.size / 1024).toFixed(1)}KB)
            </span>
          ))}
        </div>
      )}
    </div>
  </div>
);

export default UserMessageView;