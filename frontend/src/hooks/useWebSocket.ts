// frontend/src/hooks/useWebSocket.ts

import { useEffect, useRef, useCallback } from 'react';
import { useAppStore } from '../store/useAppStore';
import { wsStore, useWSState } from '../store/wsStore';
import { buildHook, BuiltHook } from './hookFactory';
import type { WSMessage, ToolExecution, Flag, Attachment } from '../store/types';
function getWebSocketUrl(): string {
  const envUrl = import.meta.env.VITE_WS_URL;

  if (envUrl) {
    // 如果是相对路径，转换为绝对URL
    if (envUrl.startsWith('/')) {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      return `${protocol}//${window.location.host}${envUrl}`;
    }
    return envUrl;
  }

  // 默认使用当前页面的host
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/ws`;
}

// 使用buildHook工厂创建WebSocket配置
const wsHook: BuiltHook = buildHook({
  name: 'WebSocket',
  url: getWebSocketUrl(),
  shouldReconnect: () => true,
  reconnectDelay: () => 3000,
  maxReconnectAttempts: () => 10,
  onConnect: () => wsStore.setConnected(true),
  onDisconnect: () => wsStore.setConnected(false),
});

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);

  const {
    setWsConnected,
    addLogEntry,
    updateLoopState,
    addToolExecution,
    addFlag,
    setIsExecuting,
  } = useAppStore();

  // 使用外部Store的状态
  const connected = useWSState((s) => s.connected);

  const handleMessage = useCallback((event: MessageEvent) => {
    try {
      const message: WSMessage = JSON.parse(event.data);

      // 设置最后消息，供控制台事件处理器使用
      wsStore.setLastMessage(message);

      // === 极简推导：从4种基础事件推导所有UI状态 ===
      switch (message.type) {
        case 'assistant_message': {
          const { content, turn } = message;

          // 1. 推导迭代状态
          if (turn) {
            updateLoopState({ currentIteration: turn });
          }

          // 2. 记录AI消息日志
          addLogEntry({
            id: `assistant-${Date.now()}`,
            timestamp: new Date(),
            type: 'info',
            message: content || '',
            iteration: turn || 0,
            node: 'think',
          });

          // 3. 推导Flag（正则提取）
          const flagMatches = content?.match(/flag\{[^}]+\}/gi) || [];
          flagMatches.forEach((flagValue: string) => {
            addFlag({
              id: `flag-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
              value: flagValue,
              timestamp: new Date(),
              iteration: turn || 0,
              copied: false,
            } as Flag);

            addLogEntry({
              id: `flag-log-${Date.now()}`,
              timestamp: new Date(),
              type: 'success',
              message: `🚩 发现Flag: ${flagValue}`,
              iteration: turn || 0,
              node: 'decide',
            });
          });

          break;
        }

        case 'tool_result': {
          const { tool_name } = message;

          // 推导工具执行记录
          const toolId = `tool-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
          addToolExecution({
            id: toolId,
            toolName: tool_name || 'unknown',
            status: 'success',
            startTime: new Date(),
            duration: 0,
            iteration: 0,
          } as ToolExecution);

          addLogEntry({
            id: `tool-${Date.now()}`,
            timestamp: new Date(),
            type: 'info',
            message: `[工具] ${tool_name} 执行完成`,
            iteration: 0,
            node: 'act',
          });

          break;
        }

        case 'complete': {
          const { reason } = message;

          // 推导任务完成状态
          const hasFlags = useAppStore.getState().flags.length > 0;
          addLogEntry({
            id: `complete-${Date.now()}`,
            timestamp: new Date(),
            type: hasFlags ? 'success' : 'info',
            message: hasFlags
              ? `✅ 任务完成，找到 ${useAppStore.getState().flags.length} 个Flag`
              : `ℹ️ 任务结束: ${reason || '未知原因'}`,
            iteration: 0,
            node: 'decide',
          });
          setIsExecuting(false);

          break;
        }

        case 'loop_detected': {
          const { tool } = message;

          addLogEntry({
            id: `loop-${Date.now()}`,
            timestamp: new Date(),
            type: 'warning',
            message: `⚠️ 检测到循环调用: ${tool}`,
            iteration: 0,
            node: 'think',
          });

          break;
        }

        // === 其他事件保持兼容 ===
        case 'connection_established': {
          addLogEntry({
            id: `conn-${Date.now()}`,
            timestamp: new Date(),
            type: 'info',
            message: '[System] Connected to CTF-Agent 2.0',
            iteration: 0,
            node: 'think',
          });
          break;
        }

        case 'interrupt': {
          addLogEntry({
            id: `interrupt-${Date.now()}`,
            timestamp: new Date(),
            type: 'info',
            message: '[System] Execution interrupted',
            iteration: 0,
            node: 'think',
          });
          setIsExecuting(false);
          break;
        }

        case 'execution_status': {
          const { isExecuting } = message.data;
          setIsExecuting(isExecuting);
          break;
        }

        default: {
          // 未知事件类型，记录为普通日志
          addLogEntry({
            id: `unknown-${Date.now()}`,
            timestamp: new Date(),
            type: 'info',
            message: JSON.stringify(message),
            iteration: 0,
            node: 'think',
          });
        }
      }
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error);
      wsStore.setError(error as Error);
    }
  }, [
    addLogEntry,
    updateLoopState,
    addToolExecution,
    addFlag,
    setIsExecuting,
  ]);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    // 检查最大重连次数
    if (reconnectAttemptsRef.current >= wsHook.maxReconnectAttempts()) {
      wsStore.setError(new Error('Max reconnect attempts reached'));
      return;
    }

    const ws = new WebSocket(wsHook.url);
    wsRef.current = ws;

    ws.onopen = () => {
      wsHook.onConnect();
      reconnectAttemptsRef.current = 0;
      wsStore.setReconnecting(false, 0);
      setWsConnected(true);
    };

    ws.onmessage = handleMessage;

    ws.onclose = () => {
      wsHook.onDisconnect();
      setWsConnected(false);

      // 使用工厂配置决定是否重连
      if (wsHook.shouldReconnect()) {
        wsStore.setReconnecting(true, reconnectAttemptsRef.current + 1);
        reconnectTimeoutRef.current = window.setTimeout(() => {
          reconnectAttemptsRef.current++;
          connect();
        }, wsHook.reconnectDelay());
      }
    };

    ws.onerror = (error) => {
      wsHook.onError(new Error('WebSocket error'));
      console.error('WebSocket error:', error);
    };
  }, [handleMessage, setWsConnected]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    wsRef.current?.close();
    wsStore.setConnected(false);
  }, []);

  const sendStart = useCallback((target: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        command: 'start',
        target: target,
      }));
      setIsExecuting(true);
    }
  }, [setIsExecuting]);

  const sendUserInput = useCallback((message: string, attachments: Attachment[]) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'user_input',
        data: {
          message,
          attachments: attachments.map(a => ({ id: a.id, name: a.name, size: a.size, type: a.type })),
        },
      }));
    }
  }, []);

  const sendInterrupt = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'interrupt',
        data: { reason: 'user_cancel' },
      }));
      setIsExecuting(false);
    }
  }, [setIsExecuting]);

  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  return {
    isConnected: connected,
    reconnectAttempts: reconnectAttemptsRef.current,
    connect,
    disconnect,
    sendStart,
    sendUserInput,
    sendInterrupt,
  };
}

// 导出配置供测试使用
export { wsHook };