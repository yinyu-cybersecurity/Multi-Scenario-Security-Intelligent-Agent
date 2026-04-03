// frontend/src/store/useAppStore.ts

import { create } from 'zustand';
import { useShallow } from 'zustand/react/shallow';
import type {
  CurrentTask,
  LoopState,
  LogEntry,
  Iteration,
  ToolExecution,
  Finding,
  Flag,
  Attachment,
  ChatMessage,
} from './types';

interface AppState {
  // Task
  currentTask: CurrentTask | null;

  // Loop State
  loopState: LoopState;

  // Log Entries
  logEntries: LogEntry[];

  // Iterations
  iterations: Iteration[];

  // Tool Executions
  toolExecutions: ToolExecution[];

  // Findings
  findings: Finding[];

  // Flags
  flags: Flag[];

  // WebSocket
  wsConnected: boolean;

  // UI State
  detailPanelCollapsed: boolean;
  detailPanelTab: 'tools' | 'findings' | 'flags';
  selectedLogEntryId: string | null;

  // Chat State
  inputValue: string;
  attachments: Attachment[];
  isDragging: boolean;
  isExecuting: boolean;
  messages: ChatMessage[];

  // Actions
  setCurrentTask: (task: CurrentTask | null) => void;
  updateLoopState: (state: Partial<LoopState>) => void;
  addLogEntry: (entry: LogEntry) => void;
  addIteration: (iteration: Iteration) => void;
  updateIteration: (number: number, update: Partial<Iteration>) => void;
  addToolExecution: (execution: ToolExecution) => void;
  updateToolExecution: (id: string, update: Partial<ToolExecution>) => void;
  addFinding: (finding: Finding) => void;
  addFlag: (flag: Flag) => void;
  setFlagCopied: (id: string, copied: boolean) => void;
  setWsConnected: (connected: boolean) => void;
  setDetailPanelCollapsed: (collapsed: boolean) => void;
  setDetailPanelTab: (tab: 'tools' | 'findings' | 'flags') => void;
  setSelectedLogEntry: (id: string | null) => void;
  reset: () => void;

  // Chat Actions
  setInputValue: (value: string) => void;
  addAttachment: (attachment: Attachment) => void;
  removeAttachment: (id: string) => void;
  clearAttachments: () => void;
  setDragging: (isDragging: boolean) => void;
  setIsExecuting: (isExecuting: boolean) => void;
  addMessage: (message: ChatMessage) => void;
}

const initialLoopState: LoopState = {
  currentNode: 'think',
  currentIteration: 0,
  maxIterations: 50,
  phase: 'idle',
  lastAction: '',
};

const initialState = {
  currentTask: null,
  loopState: initialLoopState,
  logEntries: [],
  iterations: [],
  toolExecutions: [],
  findings: [],
  flags: [],
  wsConnected: false,
  detailPanelCollapsed: false,
  detailPanelTab: 'tools' as const,
  selectedLogEntryId: null,
  // Chat state
  inputValue: '',
  attachments: [],
  isDragging: false,
  isExecuting: false,
  messages: [],
};

// Utility to generate unique IDs
let idCounter = 0;
const generateId = () => `id_${Date.now()}_${++idCounter}`;

export const useAppStore = create<AppState>((set) => ({
  ...initialState,

  setCurrentTask: (task) => set({ currentTask: task }),

  updateLoopState: (state) =>
    set((prev) => ({
      loopState: { ...prev.loopState, ...state },
    })),

  addLogEntry: (entry) =>
    set((state) => ({
      logEntries: [...state.logEntries, { ...entry, id: entry.id || generateId() }],
    })),

  addIteration: (iteration) =>
    set((state) => ({
      iterations: [...state.iterations, iteration],
    })),

  updateIteration: (num, update) =>
    set((state) => ({
      iterations: state.iterations.map((iter) =>
        iter.number === num ? { ...iter, ...update } : iter
      ),
    })),

  addToolExecution: (execution) =>
    set((state) => ({
      toolExecutions: [...state.toolExecutions, { ...execution, id: execution.id || generateId() }],
    })),

  updateToolExecution: (id, update) =>
    set((state) => ({
      toolExecutions: state.toolExecutions.map((tool) =>
        tool.id === id ? { ...tool, ...update } : tool
      ),
    })),

  addFinding: (finding) =>
    set((state) => ({
      findings: [...state.findings, { ...finding, id: finding.id || generateId() }],
    })),

  addFlag: (flag) =>
    set((state) => ({
      flags: [...state.flags, { ...flag, id: flag.id || generateId(), copied: false }],
    })),

  setFlagCopied: (id, copied) =>
    set((state) => ({
      flags: state.flags.map((flag) =>
        flag.id === id ? { ...flag, copied } : flag
      ),
    })),

  setWsConnected: (connected) => set({ wsConnected: connected }),

  setDetailPanelCollapsed: (collapsed) => set({ detailPanelCollapsed: collapsed }),

  setDetailPanelTab: (tab) => set({ detailPanelTab: tab }),

  setSelectedLogEntry: (id) => set({ selectedLogEntryId: id }),

  // Chat Actions
  setInputValue: (value) => set({ inputValue: value }),

  addAttachment: (attachment) =>
    set((state) => ({
      attachments: [...state.attachments, { ...attachment, id: attachment.id || generateId() }],
    })),

  removeAttachment: (id) =>
    set((state) => ({
      attachments: state.attachments.filter((a) => a.id !== id),
    })),

  clearAttachments: () => set({ attachments: [] }),

  setDragging: (isDragging) => set({ isDragging }),

  setIsExecuting: (isExecuting) => set({ isExecuting }),

  addMessage: (message) =>
    set((state) => ({
      messages: [...state.messages, { ...message, id: message.id || generateId() }],
    })),

  reset: () => set(initialState),
}));

// ============================================
// 选择器Hooks - 遵循Claude Code细粒度订阅模式
// ============================================

/**
 * 单值选择器 - 最低粒度，避免不必要重渲染
 */
export const useLoopState = () => useAppStore((state) => state.loopState);
export const useLogEntries = () => useAppStore((state) => state.logEntries);
export const useToolExecutions = () => useAppStore((state) => state.toolExecutions);
export const useFindings = () => useAppStore((state) => state.findings);
export const useFlags = () => useAppStore((state) => state.flags);
export const useIterations = () => useAppStore((state) => state.iterations);
export const useWsConnected = () => useAppStore((state) => state.wsConnected);
export const useIsExecuting = () => useAppStore((state) => state.isExecuting);

/**
 * 多值选择器 - 使用useShallow避免对象重建
 */
export const useChatState = () =>
  useAppStore(
    useShallow((state) => ({
      inputValue: state.inputValue,
      attachments: state.attachments,
      isDragging: state.isDragging,
      isExecuting: state.isExecuting,
    }))
  );

export const useDetailPanelState = () =>
  useAppStore(
    useShallow((state) => ({
      detailPanelCollapsed: state.detailPanelCollapsed,
      detailPanelTab: state.detailPanelTab,
      selectedLogEntryId: state.selectedLogEntryId,
    }))
  );

export const useStatsState = () =>
  useAppStore(
    useShallow((state) => ({
      findings: state.findings,
      flags: state.flags,
      toolExecutions: state.toolExecutions,
      loopState: state.loopState,
    }))
  );

/**
 * Action选择器 - 使用useShallow避免对象重建
 */
export const useChatActions = () =>
  useAppStore(
    useShallow((state) => ({
      setInputValue: state.setInputValue,
      addAttachment: state.addAttachment,
      removeAttachment: state.removeAttachment,
      clearAttachments: state.clearAttachments,
      setDragging: state.setDragging,
      setIsExecuting: state.setIsExecuting,
      addLogEntry: state.addLogEntry,
    }))
  );

export const useDetailPanelActions = () =>
  useAppStore(
    useShallow((state) => ({
      setDetailPanelCollapsed: state.setDetailPanelCollapsed,
      setDetailPanelTab: state.setDetailPanelTab,
      setSelectedLogEntry: state.setSelectedLogEntry,
    }))
  );