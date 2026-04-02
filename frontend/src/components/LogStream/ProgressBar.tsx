// frontend/src/components/LogStream/ProgressBar.tsx

import React from 'react';
import { generateProgressBar } from '../../utils/logFormatter';
import { formatDuration } from '../../utils/timeUtils';

interface ProgressBarProps {
  percent: number;
  message?: string;
  duration?: number;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  percent,
  message,
  duration,
}) => {
  return (
    <div className="flex items-center gap-2 my-1 text-xs">
      {/* Message */}
      {message && <span className="text-muted-foreground">{message}</span>}

      {/* Progress bar */}
      <span className="text-blue-500 font-mono">
        {generateProgressBar(percent, 20)}
      </span>

      {/* Percent */}
      <span className="text-muted-foreground min-w-[40px]">
        {percent}%
      </span>

      {/* Duration */}
      {duration !== undefined && (
        <span className="text-muted-foreground">
          {formatDuration(duration)}
        </span>
      )}
    </div>
  );
};