// frontend/src/components/Timeline/Timeline.tsx

import React from 'react';
import { useAppStore } from '../../store/useAppStore';
import { IterationNode } from './IterationNode';
import type { NodeType } from '../../store/types';

export const Timeline: React.FC = () => {
  const { iterations, loopState, setSelectedLogEntry } = useAppStore();

  const handleNodeClick = (node: NodeType) => {
    // Find the first log entry for this node in current iteration
    // This will scroll the log stream to that entry
    setSelectedLogEntry(`${loopState.currentIteration}-${node}`);
  };

  return (
    <div className="w-[200px] h-full bg-secondary border-r border-border overflow-y-auto p-4">
      <div className="text-xs font-medium text-muted-foreground mb-4">
        Timeline
      </div>

      {iterations.length === 0 ? (
        <div className="text-xs text-muted-foreground text-center py-8 px-4">
          No iterations yet. Start a task to begin.
        </div>
      ) : (
        <>
          {iterations
            .slice()
            .reverse()
            .map((iteration) => (
              <IterationNode
                key={iteration.number}
                iteration={iteration}
                isCurrent={iteration.number === loopState.currentIteration}
                onNodeClick={handleNodeClick}
              />
            ))}
        </>
      )}
    </div>
  );
};