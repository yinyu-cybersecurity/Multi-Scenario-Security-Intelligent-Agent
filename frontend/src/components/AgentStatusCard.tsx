import React from 'react';
import { useAppStore } from '@/store/useAppStore';
import { Brain, Zap, Eye, GitBranch } from 'lucide-react';

const nodeIcons = {
  think: Brain,
  act: Zap,
  reflect: Eye,
  decide: GitBranch,
};

const nodeLabels = {
  think: 'Think',
  act: 'Act',
  reflect: 'Reflect',
  decide: 'Decide',
};

const statusColors = {
  idle: 'text-gray-500',
  running: 'text-blue-500 animate-pulse',
  waiting: 'text-yellow-500',
  error: 'text-red-500',
  success: 'text-green-500',
};

interface Props {
  nodeType: 'think' | 'act' | 'reflect' | 'decide';
}

export const AgentStatusCard: React.FC<Props> = ({ nodeType }) => {
  // 使用统一的"loop"状态，因为现在是单循环架构
  const loopState = useAppStore((state) => state.loopState);

  const isCurrentNode = loopState?.currentNode === nodeType;
  const status = isCurrentNode ? 'running' : 'idle';

  const Icon = nodeIcons[nodeType];

  return (
    <div className={`bg-secondary rounded-lg p-4 border ${isCurrentNode ? 'border-primary' : 'border-border'}`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <Icon className={`w-5 h-5 ${statusColors[status]}`} />
          <span className="text-sm font-medium">{nodeLabels[nodeType]}</span>
        </div>
        <span className={`text-xs ${statusColors[status]}`}>
          {isCurrentNode ? 'Active' : 'Idle'}
        </span>
      </div>

      <div className="space-y-2">
        {isCurrentNode && loopState?.phase && (
          <p className="text-xs text-muted-foreground truncate">
            Phase: {loopState.phase}
          </p>
        )}

        <div className="w-full bg-muted rounded-full h-1.5">
          <div
            className="bg-primary h-1.5 rounded-full transition-all"
            style={{ width: `${(loopState.currentIteration / loopState.maxIterations) * 100}%` }}
          />
        </div>

        <div className="flex justify-between text-xs text-muted-foreground">
          <span>Iteration: {loopState.currentIteration}/{loopState.maxIterations}</span>
        </div>
      </div>
    </div>
  );
};