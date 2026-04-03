// frontend/src/components/Console/SystemMessageView.tsx
/**
 * 系统消息视图
 */

import React from 'react';
import { Info } from 'lucide-react';
import type { SystemMessage } from '../../store/consoleTypes';
import { formatTime } from '../../utils/timeUtils';

export const SystemMessageView: React.FC<{
  message: SystemMessage;
}> = ({ message }) => (
  <div className="system-message flex items-center gap-2 px-4 py-2 my-1 text-gray-500 text-sm">
    <Info size={14} />
    <span className="text-gray-400 text-xs">{formatTime(message.timestamp)}</span>
    <span>{message.content}</span>
  </div>
);

export default SystemMessageView;