// frontend/src/components/Console/SeparatorLine.tsx
/**
 * 迭代分隔线
 */

import React from 'react';
import type { SeparatorMessage } from '../../store/consoleTypes';
import { formatTime } from '../../utils/timeUtils';

export const SeparatorLine: React.FC<{
  message: SeparatorMessage;
}> = ({ message }) => (
  <div className="separator-line flex items-center gap-3 px-4 py-2 my-3">
    {/* 左侧线 */}
    <div className="flex-1 h-px bg-gray-200"></div>

    {/* 迭代标签 */}
    <div className="flex items-center gap-2 text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded">
      <span className="font-medium">Iteration {message.iterationNumber}</span>
      <span className="text-gray-400">{formatTime(message.timestamp)}</span>
    </div>

    {/* 右侧线 */}
    <div className="flex-1 h-px bg-gray-200"></div>
  </div>
);

export default SeparatorLine;