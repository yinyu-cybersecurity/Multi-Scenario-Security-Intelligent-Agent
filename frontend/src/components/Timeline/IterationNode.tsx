// frontend/src/components/Timeline/IterationNode.tsx

import React, { useState } from 'react';
import clsx from 'clsx';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { NodeIndicator } from './NodeIndicator';
import type { Iteration, NodeType } from '../../store/types';
import { getRelativeTime } from '../../utils/timeUtils';

interface IterationNodeProps {
  iteration: Iteration;
  isCurrent: boolean;
  onNodeClick: (node: NodeType) => void;
}

const nodeOrder: NodeType[] = ['think', 'act', 'reflect', 'decide'];

export const IterationNode: React.FC<IterationNodeProps> = ({
  iteration,
  isCurrent,
  onNodeClick,
}) => {
  const [expanded, setExpanded] = useState(isCurrent);

  const toggleExpand = () => setExpanded(!expanded);

  return (
    <div className="border border-border rounded-md overflow-hidden mb-2">
      {/* Header */}
      <div
        className={clsx(
          'flex items-center justify-between px-3 py-2 cursor-pointer',
          'bg-secondary hover:bg-muted transition-colors',
          isCurrent && 'bg-amber-500/10 border-l-2 border-amber-500'
        )}
        onClick={toggleExpand}
      >
        <div className="flex items-center gap-2">
          {expanded ? (
            <ChevronDown className="w-3 h-3 text-muted-foreground" />
          ) : (
            <ChevronRight className="w-3 h-3 text-muted-foreground" />
          )}
          <span className="text-xs font-medium">
            Iteration {iteration.number}
          </span>
        </div>
        <span className="text-[10px] text-muted-foreground">
          {getRelativeTime(iteration.startTime)}
        </span>
      </div>

      {/* Nodes */}
      {expanded && (
        <div className="border-t border-border">
          {nodeOrder.map((node) => {
            const nodeResult = iteration.nodes[node];
            return (
              <div
                key={node}
                className={clsx(
                  'flex items-center gap-3 px-4 py-1.5 cursor-pointer',
                  'hover:bg-muted transition-colors',
                  nodeResult.status === 'running' && 'bg-amber-500/10'
                )}
                onClick={() => onNodeClick(node)}
              >
                <NodeIndicator node={node} status={nodeResult.status} />
              </div>
            );
          })}

          {/* Summary */}
          {(iteration.findings.length > 0 || iteration.flags.length > 0) && (
            <div className="px-4 py-2 border-t border-border text-[10px] text-muted-foreground">
              {iteration.findings.length > 0 && (
                <span className="mr-3">{iteration.findings.length} findings</span>
              )}
              {iteration.flags.length > 0 && (
                <span className="text-green-500">{iteration.flags.length} flags</span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};