// frontend/src/store/wsStore.ts

import { useSyncExternalStore } from 'react';
import type { WSMessage } from './types';

/**
 * WebSocket状态接口
 */
export interface WSState {
  connected: boolean;
  error: Error | null;
  reconnecting: boolean;
  reconnectAttempts: number;
  lastMessage: WSMessage | null;
}

/**
 * WebSocket外部Store类
 * 使用useSyncExternalStore实现细粒度订阅
 */
class WebSocketStore {
  private state: WSState = {
    connected: false,
    error: null,
    reconnecting: false,
    reconnectAttempts: 0,
    lastMessage: null,
  };

  private listeners: Set<() => void> = new Set();

  /**
   * 获取当前状态
   */
  getState = (): WSState => this.state;

  /**
   * 订阅状态变化
   */
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  /**
   * 更新状态 - 引用相等性检查
   */
  setState = (updater: (prev: WSState) => WSState): void => {
    const next = updater(this.state);
    // 引用相等性检查，避免不必要的重渲染
    if (Object.is(next, this.state)) return;
    this.state = next;
    this.listeners.forEach((l) => l());
  };

  /**
   * 设置连接状态
   */
  setConnected = (connected: boolean): void => {
    this.setState((prev) => ({
      ...prev,
      connected,
      reconnecting: connected ? false : prev.reconnecting,
      error: connected ? null : prev.error,
    }));
  };

  /**
   * 设置错误
   */
  setError = (error: Error | null): void => {
    this.setState((prev) => ({ ...prev, error }));
  };

  /**
   * 设置重连状态
   */
  setReconnecting = (reconnecting: boolean, attempts?: number): void => {
    this.setState((prev) => ({
      ...prev,
      reconnecting,
      reconnectAttempts: attempts ?? prev.reconnectAttempts,
    }));
  };

  /**
   * 设置最后消息
   */
  setLastMessage = (message: WSMessage | null): void => {
    this.setState((prev) => ({ ...prev, lastMessage: message }));
  };
}

// 单例实例
export const wsStore = new WebSocketStore();

/**
 * 使用WebSocket状态的选择器Hook
 * 遵循Claude Code的useSyncExternalStore模式
 *
 * @example
 * const connected = useWSState(s => s.connected);
 * const error = useWSState(s => s.error);
 */
export function useWSState<T>(selector: (state: WSState) => T): T {
  return useSyncExternalStore(
    wsStore.subscribe,
    () => selector(wsStore.getState())
  );
}