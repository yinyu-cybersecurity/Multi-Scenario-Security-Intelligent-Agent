// frontend/src/components/DecisionFlow/DecisionFlow.tsx

/**
 * 决策流组件 - 完全复刻Claude Code的决策过程展示
 *
 * 设计原则:
 * 1. 实时展示AI决策过程
 * 2. 脉冲动画表示当前执行
 * 3. 可折叠展开详情
 * 4. 支持快捷键导航
 */

import React, { useState, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CheckCircle,
  AlertCircle,
  Loader2,
  ChevronDown,
} from 'lucide-react';
import './DecisionFlow.css';

export type DecisionStatus = 'pending' | 'running' | 'success' | 'error';

export interface DecisionStep {
  id: string;
  type: 'search' | 'read' | 'write' | 'bash' | 'tool' | 'think';
  title: string;
  description: string;
  status: DecisionStatus;
  startTime: Date;
  endTime?: Date;
  details?: string;
  result?: string;
  error?: string;
}

export interface DecisionFlowProps {
  steps: DecisionStep[];
  currentStepId?: string;
}

const StatusIcon: React.FC<{ status: DecisionStatus }> = ({ status }) => {
  const iconProps = { size: 16 };

  if (status === 'running') {
    return <Loader2 {...iconProps} className="status-icon running" />;
  }
  if (status === 'success') {
    return <CheckCircle {...iconProps} className="status-icon success" />;
  }
  if (status === 'error') {
    return <AlertCircle {...iconProps} className="status-icon error" />;
  }
  return <ChevronDown {...iconProps} className="status-icon pending" />;
};

const DecisionCard: React.FC<{
  step: DecisionStep;
  isExpanded: boolean;
  onToggle: () => void;
}> = ({ step, isExpanded, onToggle }) => {
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.ctrlKey && e.key === 'o') {
      e.preventDefault();
      onToggle();
    }
  }, [onToggle]);

  return (
    <motion.div
      className={`decision-card ${step.status}`}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      onKeyDown={handleKeyDown}
      tabIndex={0}
    >
      <div className="decision-card-header" onClick={onToggle}>
        <div className="decision-card-left">
          <StatusIcon status={step.status} />
          <span className="decision-card-title">{step.title}</span>
          {step.status === 'running' && (
            <span className="pulse-indicator">
              <span className="pulse-dot"></span>
            </span>
          )}
        </div>
        <div className="decision-card-right">
          <span className="expand-hint">(ctrl+o)</span>
          <motion.div animate={{ rotate: isExpanded ? 180 : 0 }}>
            <ChevronDown size={14} />
          </motion.div>
        </div>
      </div>

      <AnimatePresence>
        {isExpanded && step.details && (
          <motion.div
            className="decision-card-details"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
          >
            <pre className="decision-code">{step.details}</pre>
            {step.result && (
              <div className="decision-result">
                <pre>{step.result}</pre>
              </div>
            )}
            {step.error && (
              <div className="decision-error">
                <pre>{step.error}</pre>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

export const DecisionFlow: React.FC<DecisionFlowProps> = ({
  steps,
  currentStepId,
}) => {
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (currentStepId) {
      setExpandedSteps(prev => new Set([...prev, currentStepId]));
    }
  }, [currentStepId]);

  const toggleStep = useCallback((stepId: string) => {
    setExpandedSteps(prev => {
      const next = new Set(prev);
      if (next.has(stepId)) {
        next.delete(stepId);
      } else {
        next.add(stepId);
      }
      return next;
    });
  }, []);

  return (
    <div className="decision-flow">
      <AnimatePresence mode="popLayout">
        {steps.map((step) => (
          <DecisionCard
            key={step.id}
            step={step}
            isExpanded={expandedSteps.has(step.id)}
            onToggle={() => toggleStep(step.id)}
          />
        ))}
      </AnimatePresence>
    </div>
  );
};

export default DecisionFlow;