import { create } from 'zustand';

export interface AgentStatus {
  agentType: 'explore' | 'plan' | 'attack' | 'verify';
  status: 'idle' | 'running' | 'waiting' | 'error' | 'success';
  currentTask: string;
  progress: number;
  lastUpdate: Date;
  toolsUsed: string[];
}

export interface ToolExecution {
  id: string;
  toolName: string;
  startTime: Date;
  duration: number;
  status: 'pending' | 'running' | 'success' | 'error';
  output: string;
  error?: string;
}

export interface Finding {
  id: string;
  type: 'endpoint' | 'vuln' | 'credential' | 'flag';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  evidence: string;
  timestamp: Date;
}

export interface Task {
  id: string;
  title: string;
  description: string;
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  createdAt: Date;
}

interface AppState {
  // 当前任务
  currentTask: Task | null;

  // Agent状态
  agents: Record<string, AgentStatus>;

  // 工具执行历史
  toolExecutions: ToolExecution[];

  // 发现列表
  findings: Finding[];

  // Flags
  flags: string[];

  // Token统计
  tokenStats: {
    total: number;
    byModel: Record<string, number>;
    cost: number;
  };

  // WebSocket连接
  wsConnected: boolean;

  // Actions
  setCurrentTask: (task: Task | null) => void;
  updateAgentStatus: (agentType: string, status: AgentStatus) => void;
  addToolExecution: (execution: ToolExecution) => void;
  addFinding: (finding: Finding) => void;
  addFlag: (flag: string) => void;
  setWsConnected: (connected: boolean) => void;
  reset: () => void;
}

const initialState = {
  currentTask: null,
  agents: {},
  toolExecutions: [],
  findings: [],
  flags: [],
  tokenStats: {
    total: 0,
    byModel: {},
    cost: 0,
  },
  wsConnected: false,
};

export const useAppStore = create<AppState>((set) => ({
  ...initialState,

  setCurrentTask: (task) => set({ currentTask: task }),

  updateAgentStatus: (agentType, status) =>
    set((state) => ({
      agents: { ...state.agents, [agentType]: status },
    })),

  addToolExecution: (execution) =>
    set((state) => ({
      toolExecutions: [...state.toolExecutions, execution],
    })),

  addFinding: (finding) =>
    set((state) => ({
      findings: [...state.findings, finding],
    })),

  addFlag: (flag) =>
    set((state) => ({
      flags: [...state.flags, flag],
    })),

  setWsConnected: (connected) => set({ wsConnected: connected }),

  reset: () => set(initialState),
}));