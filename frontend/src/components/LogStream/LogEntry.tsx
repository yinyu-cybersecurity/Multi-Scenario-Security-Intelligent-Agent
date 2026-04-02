// frontend/src/components/LogStream/LogEntry.tsx

import React from 'react';
import clsx from 'clsx';
import type { LogEntry as LogEntryType } from '../../store/types';
import { LOG_COLORS, LOG_PREFIXES } from '../../utils/logFormatter';

interface LogEntryProps {
  entry: LogEntryType;
  isSelected?: boolean;
  onClick?: () => void;
}

export const LogEntryComponent: React.FC<LogEntryProps> = ({
  entry,
  isSelected,
  onClick,
}) => {
  const prefix = LOG_PREFIXES[entry.type];
  const colorClass = LOG_COLORS[entry.type];

  // Check if details contain tool output
  const outputStr: string = entry.details?.output && typeof entry.details.output === 'string'
    ? entry.details.output
    : '';
  const toolOutputLines: string[] = outputStr
    ? outputStr.split('\n').map((line: string) => `│ ${line}`)
    : [];

  return (
    <div
      className={clsx(
        'my-0.5 cursor-pointer hover:bg-muted/30 rounded px-1',
        isSelected && 'bg-amber-500/10'
      )}
      onClick={onClick}
    >
      {/* Main log line */}
      <span className={colorClass}>
        <span className="font-semibold">{prefix}</span>
        {' '}
        <span className="text-foreground">{entry.message}</span>
      </span>

      {/* Tool output with indentation */}
      {toolOutputLines.length > 0 && (
        <div className="border-l border-border pl-2 ml-1 mt-1 text-muted-foreground">
          {toolOutputLines.map((line: string, i: number) => (
            <div key={i} className="whitespace-pre text-xs">
              {line}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// Separator component
export const LogSeparator: React.FC<{ timestamp: Date }> = ({ timestamp }) => {
  const year = timestamp.getFullYear();
  const month = String(timestamp.getMonth() + 1).padStart(2, '0');
  const day = String(timestamp.getDate()).padStart(2, '0');
  const hours = String(timestamp.getHours()).padStart(2, '0');
  const minutes = String(timestamp.getMinutes()).padStart(2, '0');
  const seconds = String(timestamp.getSeconds()).padStart(2, '0');
  const formatted = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;

  return (
    <div className="text-muted-foreground text-xs my-2">
      [{formatted}] {'─'.repeat(50)}
    </div>
  );
};