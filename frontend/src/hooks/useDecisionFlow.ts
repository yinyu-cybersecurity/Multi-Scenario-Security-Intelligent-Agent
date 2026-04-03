// frontend/src/hooks/useDecisionFlow.ts

/**
 * 决策流Hook - 管理决策步骤状态
 *
 * 设计原则:
 * 1. 步骤可动态添加/更新
 * 2. 当前执行步骤高亮
 * 3. 支持撤销和重做（可选）
 */

import { useState, useCallback } from 'react';
import type { DecisionStep, DecisionStatus } from '../components/DecisionFlow/DecisionFlow';

export interface DecisionFlowState {
  steps: DecisionStep[];
  currentStepId: string | null;
  isExecuting: boolean;
}

export function useDecisionFlow() {
  const [state, setState] = useState<DecisionFlowState>({
    steps: [],
    currentStepId: null,
    isExecuting: false,
  });

  const addStep = useCallback((
    step: Omit<DecisionStep, 'id' | 'startTime'>
  ): string => {
    const id = `step-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const newStep: DecisionStep = {
      ...step,
      id,
      startTime: new Date(),
    };

    setState(prev => ({
      ...prev,
      steps: [...prev.steps, newStep],
      currentStepId: step.status === 'running' ? id : prev.currentStepId,
      isExecuting: step.status === 'running',
    }));

    return id;
  }, []);

  const updateStep = useCallback((
    stepId: string,
    updates: Partial<DecisionStep>
  ) => {
    setState(prev => ({
      ...prev,
      steps: prev.steps.map(step =>
        step.id === stepId ? { ...step, ...updates } : step
      ),
      currentStepId: updates.status === 'running'
        ? stepId
        : prev.currentStepId,
      isExecuting: updates.status === 'running' ? true : prev.isExecuting,
    }));
  }, []);

  const completeStep = useCallback((
    stepId: string,
    result?: string,
    error?: string
  ) => {
    const status: DecisionStatus = error ? 'error' : 'success';
    updateStep(stepId, {
      status,
      endTime: new Date(),
      result,
      error,
    });

    setState(prev => ({
      ...prev,
      isExecuting: false,
    }));
  }, [updateStep]);

  const clearSteps = useCallback(() => {
    setState({
      steps: [],
      currentStepId: null,
      isExecuting: false,
    });
  }, []);

  const getStepById = useCallback((stepId: string): DecisionStep | undefined => {
    return state.steps.find(step => step.id === stepId);
  }, [state.steps]);

  const getStepsByStatus = useCallback((status: DecisionStatus): DecisionStep[] => {
    return state.steps.filter(step => step.status === status);
  }, [state.steps]);

  return {
    ...state,
    addStep,
    updateStep,
    completeStep,
    clearSteps,
    getStepById,
    getStepsByStatus,
  };
}

export default useDecisionFlow;