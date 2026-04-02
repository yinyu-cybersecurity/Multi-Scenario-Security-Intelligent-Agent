// frontend/src/components/DetailPanel/ToolCard.tsx

import React from 'react';
import clsx from 'clsx';
import { CheckCircle, XCircle, ExternalLink } from 'lucide-react';
import type { ToolExecution } from '../../store/types';
import { formatDuration } from '../../utils/timeUtils';

interface ToolCardProps {
  tool: ToolExecution;
  onClick: () => void;
}

export const ToolCard: React.FC<ToolCardProps> = ({ tool, onClick }) => {
  const StatusIcon = tool.status === 'success' ? CheckCircle : XCircle;
  const statusColor =
    tool.status === 'success'
      ? 'text-green-500'
      : tool.status === 'error'
      ? 'text-red-500'
      : 'text-yellow-500';

  return (
    <div
      className="bg-secondary border border-border rounded-md p-3 mb-2 cursor-pointer hover:bg-muted transition-colors"
      onClick={onClick}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-semibold">{tool.toolName}</span>
        <span className="text-[10px] text-muted-foreground">
          {tool.duration ? formatDuration(tool.duration) : '...'}
        </span>
      </div>

      <div className="text-xs text-muted-foreground">
        <div className="flex items-center gap-2 mb-1">
          <StatusIcon className={clsx('w-3 h-3', statusColor)} />
          <span className="capitalize">{tool.status}</span>
        </div>

        {tool.command && (
          <div className="font-mono truncate bg-primary/30 p-1.5 rounded mt-1">
            $ {tool.command}
          </div>
        )}

        {tool.error && (
          <div className="text-red-400 mt-1 truncate">
            {tool.error}
          </div>
        )}
      </div>

      <div className="flex gap-2 mt-2">
        <button className="text-[10px] px-2 py-1 bg-muted rounded border border-border hover:bg-secondary">
          <ExternalLink className="w-3 h-3 inline mr-1" />
          View
        </button>
      </div>
    </div>
  );
};