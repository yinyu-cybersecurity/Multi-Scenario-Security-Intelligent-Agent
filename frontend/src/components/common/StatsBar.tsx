// frontend/src/components/common/StatsBar.tsx

import React from 'react';
import { Target, Flag, Wrench, Brain, Repeat } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';

export const StatsBar: React.FC = () => {
  const { findings, flags, toolExecutions, loopState } = useAppStore();

  const stats = [
    {
      icon: Target,
      label: 'Findings',
      value: findings.length,
      color: 'text-blue-500',
    },
    {
      icon: Flag,
      label: 'Flags',
      value: flags.length,
      color: 'text-green-500',
    },
    {
      icon: Wrench,
      label: 'Tools',
      value: toolExecutions.length,
      color: 'text-cyan-500',
    },
    {
      icon: Brain,
      label: 'Skills',
      value: 15,
      color: 'text-purple-500',
    },
    {
      icon: Repeat,
      label: 'Iterations',
      value: `${loopState.currentIteration}/${loopState.maxIterations}`,
      color: 'text-amber-500',
    },
  ];

  return (
    <div className="grid grid-cols-5 gap-4 px-6 py-3 border-b border-border bg-secondary/50">
      {stats.map((stat) => (
        <div
          key={stat.label}
          className="flex items-center gap-2 px-4 py-2 bg-muted/30 rounded-lg"
        >
          <stat.icon className={`w-4 h-4 ${stat.color}`} />
          <div>
            <div className="text-xs text-muted-foreground">{stat.label}</div>
            <div className="text-lg font-bold">{stat.value}</div>
          </div>
        </div>
      ))}
    </div>
  );
};