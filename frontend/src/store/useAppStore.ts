// frontend/src/store/useAppStore.ts

import { create } from 'zustand';
import type {
  CurrentTask,
  LoopState,
  LogEntry,
  Iteration,
  ToolExecution,
  Finding,
  Flag,
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

  reset: () => set(initialState),
}));