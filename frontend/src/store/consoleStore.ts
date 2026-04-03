// frontend/src/store/consoleStore.ts
/**
 * 控制台状态管理 - Zustand Store
 */

import { create } from 'zustand';
import { useShallow } from 'zustand/react/shallow';
import type {
  ConsoleMessage,
  UserMessage,
  AssistantMessage,
  ToolCallMessage,
  ErrorMessage,
  SeparatorMessage,
  SystemMessage,
  ToolCallStatus,
} from './consoleTypes';
import type { Attachment } from './types';

// ID计数器
let idCounter = 0;
const generateId = () => `console_${Date.now()}_${++idCounter}`;

/**
 * 控制台状态接口
 */
interface ConsoleState {
  // 消息流
  messages: ConsoleMessage[];

  // 当前运行的工具调用ID
  activeToolCallId: string | null;

  // 展开的工具调用ID集合
  expandedToolCalls: Set<string>;

  // 滚动状态
  autoScroll: boolean;

  // 搜索过滤
  searchFilter: string;

  // 当前迭代
  currentIteration: number;

  // Actions
  addUserMessage: (content: string, attachments?: Attachment[]) => string;
  addAssistantMessage: (content: string, isStreaming?: boolean, iteration?: number) => string;
  startToolCall: (params: {
    toolName: string;
    command?: string;
    description?: string;
    iteration?: number;
  }) => string;
  completeToolCall: (id: string, output: string, duration: number) => void;
  errorToolCall: (id: string, error: string) => void;
  addSeparator: (iterationNumber: number) => string;
  addError: (content: string, stackTrace?: string) => string;
  addSystemMessage: (content: string) => string;
  toggleExpand: (id: string) => void;
  setAutoScroll: (auto: boolean) => void;
  setSearchFilter: (filter: string) => void;
  setCurrentIteration: (iteration: number) => void;
  clearConsole: () => void;
}

/**
 * 初始状态
 */
const initialState = {
  messages: [] as ConsoleMessage[],
  activeToolCallId: null as string | null,
  expandedToolCalls: new Set<string>(),
  autoScroll: true,
  searchFilter: '',
  currentIteration: 0,
};

/**
 * 控制台Store
 */
export const useConsoleStore = create<ConsoleState>((set, get) => ({
  ...initialState,

  /**
   * 添加用户消息
   */
  addUserMessage: (content, attachments) => {
    const id = generateId();
    const iteration = get().currentIteration;
    const message: UserMessage = {
      id,
      type: 'user',
      content,
      attachments,
      timestamp: new Date(),
      iteration,
    };
    set(state => ({ messages: [...state.messages, message] }));
    return id;
  },

  /**
   * 添加AI消息
   */
  addAssistantMessage: (content, isStreaming = false, iteration) => {
    const id = generateId();
    const iter = iteration ?? get().currentIteration;
    const message: AssistantMessage = {
      id,
      type: 'assistant',
      content,
      isStreaming,
      timestamp: new Date(),
      iteration: iter,
    };
    set(state => ({ messages: [...state.messages, message] }));
    return id;
  },

  /**
   * 开始工具调用
   */
  startToolCall: ({ toolName, command, description, iteration }) => {
    const id = generateId();
    const iter = iteration ?? get().currentIteration;
    const timestamp = new Date();
    const message: ToolCallMessage = {
      id,
      type: 'tool_call',
      toolName,
      command,
      description,
      status: 'running',
      startTime: timestamp,
      timestamp,
      isExpanded: true, // 运行中默认展开
      iteration: iter,
    };
    set(state => ({
      messages: [...state.messages, message],
      activeToolCallId: id,
      expandedToolCalls: new Set([...state.expandedToolCalls, id]),
    }));
    return id;
  },

  /**
   * 完成工具调用
   */
  completeToolCall: (id, output, duration) => {
    set(state => ({
      messages: state.messages.map(msg =>
        msg.id === id && msg.type === 'tool_call'
          ? {
              ...msg,
              status: 'completed' as ToolCallStatus,
              endTime: new Date(),
              output,
              duration,
              isExpanded: false, // 完成后默认折叠
            }
          : msg
      ),
      activeToolCallId: state.activeToolCallId === id ? null : state.activeToolCallId,
      expandedToolCalls: state.activeToolCallId === id
        ? new Set([...state.expandedToolCalls].filter(x => x !== id))
        : state.expandedToolCalls,
    }));
  },

  /**
   * 工具调用出错
   */
  errorToolCall: (id, error) => {
    set(state => ({
      messages: state.messages.map(msg =>
        msg.id === id && msg.type === 'tool_call'
          ? {
              ...msg,
              status: 'error' as ToolCallStatus,
              endTime: new Date(),
              error,
            }
          : msg
      ),
      activeToolCallId: state.activeToolCallId === id ? null : state.activeToolCallId,
    }));
  },

  /**
   * 添加迭代分隔线
   */
  addSeparator: (iterationNumber) => {
    const id = generateId();
    const message: SeparatorMessage = {
      id,
      type: 'separator',
      iterationNumber,
      timestamp: new Date(),
      iteration: iterationNumber,
    };
    set(state => ({ messages: [...state.messages, message] }));
    return id;
  },

  /**
   * 添加错误消息
   */
  addError: (content, stackTrace) => {
    const id = generateId();
    const iteration = get().currentIteration;
    const message: ErrorMessage = {
      id,
      type: 'error',
      content,
      stackTrace,
      timestamp: new Date(),
      iteration,
    };
    set(state => ({ messages: [...state.messages, message] }));
    return id;
  },

  /**
   * 添加系统消息
   */
  addSystemMessage: (content) => {
    const id = generateId();
    const iteration = get().currentIteration;
    const message: SystemMessage = {
      id,
      type: 'system',
      content,
      timestamp: new Date(),
      iteration,
    };
    set(state => ({ messages: [...state.messages, message] }));
    return id;
  },

  /**
   * 切换展开/折叠
   */
  toggleExpand: (id) => {
    set(state => {
      const next = new Set(state.expandedToolCalls);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return { expandedToolCalls: next };
    });
  },

  /**
   * 设置自动滚动
   */
  setAutoScroll: (auto) => set({ autoScroll: auto }),

  /**
   * 设置搜索过滤
   */
  setSearchFilter: (filter) => set({ searchFilter: filter }),

  /**
   * 设置当前迭代
   */
  setCurrentIteration: (iteration) => set({ currentIteration: iteration }),

  /**
   * 清空控制台
   */
  clearConsole: () => set({
    messages: [],
    activeToolCallId: null,
    expandedToolCalls: new Set(),
    currentIteration: 0,
  }),
}));

// ============================================
// 选择器Hooks - 细粒度订阅
// ============================================

/**
 * 消息列表选择器
 */
export const useConsoleMessages = () => useConsoleStore(state => state.messages);

/**
 * 活动工具调用ID
 */
export const useActiveToolCallId = () => useConsoleStore(state => state.activeToolCallId);

/**
 * 自动滚动状态
 */
export const useAutoScroll = () => useConsoleStore(state => state.autoScroll);

/**
 * 当前迭代
 */
export const useCurrentIteration = () => useConsoleStore(state => state.currentIteration);

/**
 * 控制台Actions
 */
export const useConsoleActions = () =>
  useConsoleStore(
    useShallow(state => ({
      addUserMessage: state.addUserMessage,
      addAssistantMessage: state.addAssistantMessage,
      startToolCall: state.startToolCall,
      completeToolCall: state.completeToolCall,
      errorToolCall: state.errorToolCall,
      addSeparator: state.addSeparator,
      addError: state.addError,
      addSystemMessage: state.addSystemMessage,
      toggleExpand: state.toggleExpand,
      setAutoScroll: state.setAutoScroll,
      setSearchFilter: state.setSearchFilter,
      setCurrentIteration: state.setCurrentIteration,
      clearConsole: state.clearConsole,
    }))
  );