// frontend/src/components/Timeline/NodeIndicator.tsx

import React from 'react';
import clsx from 'clsx';
import type { NodeType } from '../../store/types';

interface NodeIndicatorProps {
  node: NodeType;
  status: 'pending' | 'running' | 'completed' | 'error';
  size?: 'sm' | 'md';
}

const nodeLabels: Record<NodeType, string> = {
  think: 'Think',
  act: 'Act',
  reflect: 'Reflect',
  decide: 'Decide',
};

export const NodeIndicator: React.FC<NodeIndicatorProps> = ({
  node,
  status,
  size = 'sm',
}) => {
  const sizeClasses = size === 'sm' ? 'w-2 h-2 text-[10px]' : 'w-3 h-3 text-xs';

  return (
    <div className="flex items-center gap-2">
      {/* Status indicator dot */}
      <span
        className={clsx(
          'rounded-full',
          sizeClasses,
          status === 'running' && 'bg-amber-500 animate-pulse',
          status === 'completed' && 'bg-green-500',
          status === 'error' && 'bg-red-500',
          status === 'pending' && 'bg-gray-500'
        )}
      />

      {/* Node name */}
      <span
        className={clsx(
          size === 'sm' ? 'text-xs' : 'text-sm',
          status === 'running' && 'text-amber-500 font-medium',
          status === 'completed' && 'text-green-500',
          status === 'error' && 'text-red-500',
          status === 'pending' && 'text-gray-500'
        )}
      >
        {nodeLabels[node]}
      </span>

      {/* Running indicator */}
      {status === 'running' && (
        <span className="text-amber-500 text-[10px] animate-pulse">
          running
        </span>
      )}
    </div>
  );
};