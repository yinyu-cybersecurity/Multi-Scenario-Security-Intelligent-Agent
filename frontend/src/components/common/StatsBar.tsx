// frontend/src/components/common/StatsBar.tsx

import React, { useState, useEffect } from 'react';
import { Target, Flag, Wrench, Brain, Repeat, Wifi, WifiOff, Clock } from 'lucide-react';
import { useStatsState } from '../../store/useAppStore';
import { useWSState } from '../../store/wsStore';

export const StatsBar: React.FC = () => {
  const { findings, flags, toolExecutions, loopState } = useStatsState();
  const connected = useWSState((s) => s.connected);
  const [skillsCount, setSkillsCount] = useState(0);
  const [executionTime, setExecutionTime] = useState(0);
  const [isExecuting, setIsExecuting] = useState(false);

  useEffect(() => {
    fetch('/api/skills/count')
      .then(res => res.json())
      .then(data => setSkillsCount(data.count || 0))
      .catch(() => setSkillsCount(0));
  }, []);

  // 执行计时器
  useEffect(() => {
    let interval: number | null = null;

    if (isExecuting) {
      interval = window.setInterval(() => {
        setExecutionTime(prev => prev + 1);
      }, 1000);
    } else if (interval) {
      window.clearInterval(interval);
    }

    return () => {
      if (interval) window.clearInterval(interval);
    };
  }, [isExecuting]);

  // 监听执行状态（从AppStore）
  useEffect(() => {
    const checkExecuting = () => {
      // 使用window对象检查执行状态
      const checkInterval = setInterval(() => {
        // 简化状态检查，直接从DOM读取
        const runningIndicator = document.querySelector('[data-running]');
        setIsExecuting(!!runningIndicator);
      }, 500);
      return () => clearInterval(checkInterval);
    };

    return checkExecuting();
  }, []);

  // 格式化时间（00:00:00）
  const formatTime = (seconds: number) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const stats = [
    {
      icon: connected ? Wifi : WifiOff,
      label: 'Connection',
      value: connected ? 'Online' : 'Offline',
      color: connected ? 'text-green-500' : 'text-red-500',
    },
    {
      icon: Clock,
      label: 'Time',
      value: formatTime(executionTime),
      color: 'text-blue-500',
    },
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
      value: skillsCount,
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
    <div className="grid grid-cols-7 gap-2 px-4 py-2 border-b border-border bg-secondary/50">
      {stats.map((stat) => (
        <div
          key={stat.label}
          className="flex items-center gap-2 px-3 py-1.5 bg-muted/30 rounded-lg"
        >
          <stat.icon className={`w-4 h-4 ${stat.color}`} />
          <div>
            <div className="text-xs text-muted-foreground">{stat.label}</div>
            <div className="text-sm font-bold">{stat.value}</div>
          </div>
        </div>
      ))}
    </div>
  );
};