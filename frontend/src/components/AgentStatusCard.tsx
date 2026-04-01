import React from 'react';
import { useAppStore, AgentStatus } from '@/store/useAppStore';
import { Activity, Target, Shield, CheckCircle } from 'lucide-react';

const agentIcons = {
  explore: Target,
  plan: Activity,
  attack: Shield,
  verify: CheckCircle,
};

const statusColors = {
  idle: 'text-gray-500',
  running: 'text-blue-500 animate-pulse',
  waiting: 'text-yellow-500',
  error: 'text-red-500',
  success: 'text-green-500',
};

interface Props {
  agentType: 'explore' | 'plan' | 'attack' | 'verify';
}

export const AgentStatusCard: React.FC<Props> = ({ agentType }) => {
  const agent = useAppStore((state) => state.agents[agentType]) as AgentStatus | undefined;

  if (!agent) {
    return (
      <div className="bg-secondary rounded-lg p-4 border border-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {React.createElement(agentIcons[agentType], { className: 'w-5 h-5 text-gray-500' })}
            <span className="text-sm font-medium capitalize">{agentType}</span>
          </div>
          <span className="text-xs text-muted-foreground">Not started</span>
        </div>
      </div>
    );
  }

  const Icon = agentIcons[agentType];

  return (
    <div className="bg-secondary rounded-lg p-4 border border-border">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <Icon className={`w-5 h-5 ${statusColors[agent.status]}`} />
          <span className="text-sm font-medium capitalize">{agentType}</span>
        </div>
        <span className={`text-xs ${statusColors[agent.status]}`}>
          {agent.status}
        </span>
      </div>

      <div className="space-y-2">
        <p className="text-xs text-muted-foreground truncate">
          {agent.currentTask}
        </p>

        <div className="w-full bg-muted rounded-full h-1.5">
          <div
            className="bg-primary h-1.5 rounded-full transition-all"
            style={{ width: `${agent.progress}%` }}
          />
        </div>

        {agent.toolsUsed.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {agent.toolsUsed.slice(0, 3).map((tool) => (
              <span
                key={tool}
                className="px-2 py-0.5 bg-muted text-xs rounded"
              >
                {tool}
              </span>
            ))}
            {agent.toolsUsed.length > 3 && (
              <span className="px-2 py-0.5 bg-muted text-xs rounded">
                +{agent.toolsUsed.length - 3}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
};