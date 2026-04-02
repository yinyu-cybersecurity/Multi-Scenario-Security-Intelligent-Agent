// frontend/src/hooks/useWebSocket.ts

import { useEffect, useRef, useCallback } from 'react';
import { useAppStore } from '../store/useAppStore';
import { wsStore, useWSState } from '../store/wsStore';
import { buildHook, BuiltHook } from './hookFactory';
import type { WSMessage, NodeType, LogEntry, ToolExecution, Finding, Flag, Iteration, Attachment } from '../store/types';

// 使用buildHook工厂创建WebSocket配置
const wsHook: BuiltHook = buildHook({
  name: 'WebSocket',
  url: import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws',
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
    updateToolExecution,
    addFinding,
    addFlag,
    addIteration,
    setIsExecuting,
  } = useAppStore();

  // 使用外部Store的状态
  const connected = useWSState((s) => s.connected);

  const handleMessage = useCallback((event: MessageEvent) => {
    try {
      const message: WSMessage = JSON.parse(event.data);

      switch (message.type) {
        case 'connection_established': {
          // 连接成功
          addLogEntry({
            id: `conn-${Date.now()}`,
            timestamp: new Date(),
            type: 'info',
            message: '[System] Connected to CTF-Agent 2.0',
            iteration: 0,
            node: 'think',
          } as LogEntry);
          break;
        }

        case 'task_start': {
          const { target, description } = message.data;
          addLogEntry({
            id: `task-${Date.now()}`,
            timestamp: new Date(),
            type: 'info',
            message: `[Task] Starting: ${target}`,
            iteration: 0,
            node: 'think',
          } as LogEntry);
          break;
        }

        case 'iteration_start': {
          const { iteration, timestamp } = message.data;
          addIteration({
            number: iteration,
            startTime: new Date(timestamp),
            nodes: {
              think: { status: 'pending', startTime: new Date() },
              act: { status: 'pending', startTime: new Date() },
              reflect: { status: 'pending', startTime: new Date() },
              decide: { status: 'pending', startTime: new Date() },
            },
            findings: [],
            flags: [],
          } as Iteration);
          updateLoopState({ currentIteration: iteration });
          addLogEntry({
            id: `iter-${Date.now()}`,
            timestamp: new Date(),
            type: 'info',
            message: `Iteration ${iteration} started`,
            iteration,
            node: 'think',
          } as LogEntry);
          break;
        }

        case 'node_start': {
          const { node, iteration } = message.data;
          updateLoopState({ currentNode: node as NodeType });
          addLogEntry({
            id: `node-${Date.now()}`,
            timestamp: new Date(),
            type: node as LogEntry['type'],
            message: `Starting ${node}...`,
            iteration,
            node: node as NodeType,
          } as LogEntry);
          break;
        }

        case 'node_end': {
          const { node, iteration, result } = message.data;
          addLogEntry({
            id: `node-end-${Date.now()}`,
            timestamp: new Date(),
            type: node as LogEntry['type'],
            message: result,
            iteration,
            node: node as NodeType,
          } as LogEntry);
          break;
        }

        case 'log': {
          addLogEntry({
            ...message.data,
            id: message.data.id || `log-${Date.now()}`,
            timestamp: new Date(message.data.timestamp),
          } as LogEntry);
          break;
        }

        case 'tool_start': {
          addToolExecution({
            ...message.data,
            id: message.data.id || `tool-${Date.now()}`,
            startTime: new Date(message.data.startTime),
          } as ToolExecution);
          break;
        }

        case 'tool_complete': {
          const { id, result, duration } = message.data;
          updateToolExecution(id, {
            status: 'success',
            duration,
            output: JSON.stringify(result, null, 2),
          });
          break;
        }

        case 'finding': {
          addFinding({
            ...message.data,
            id: message.data.id || `finding-${Date.now()}`,
            timestamp: new Date(message.data.timestamp),
          } as Finding);
          break;
        }

        case 'flag': {
          addFlag({
            ...message.data,
            id: message.data.id || `flag-${Date.now()}`,
            timestamp: new Date(message.data.timestamp),
          } as Flag);
          break;
        }

        case 'iteration_end': {
          const { iteration } = message.data;
          addLogEntry({
            id: `iter-end-${Date.now()}`,
            timestamp: new Date(),
            type: 'info',
            message: `Iteration ${iteration} completed`,
            iteration,
            node: 'decide',
          } as LogEntry);
          break;
        }

        case 'task_complete': {
          const { success, flags } = message.data;
          addLogEntry({
            id: `task-${Date.now()}`,
            timestamp: new Date(),
            type: success ? 'success' : 'error',
            message: success
              ? `Task completed successfully. Found ${flags.length} flags.`
              : 'Task completed without finding flags.',
            iteration: 0,
            node: 'decide',
          } as LogEntry);
          setIsExecuting(false);
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
          } as LogEntry);
          setIsExecuting(false);
          break;
        }

        case 'file_uploaded': {
          const { filename, size } = message.data;
          const sizeStr = size > 1024 * 1024
            ? `${(size / (1024 * 1024)).toFixed(1)}MB`
            : `${(size / 1024).toFixed(1)}KB`;
          addLogEntry({
            id: `file-${Date.now()}`,
            timestamp: new Date(),
            type: 'info',
            message: `[File] Uploaded: ${filename} (${sizeStr})`,
            iteration: 0,
            node: 'think',
          } as LogEntry);
          break;
        }

        case 'execution_status': {
          const { isExecuting } = message.data;
          setIsExecuting(isExecuting);
          break;
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
    updateToolExecution,
    addFinding,
    addFlag,
    addIteration,
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

  const sendUserInput = useCallback((message: string, attachments: Attachment[]) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'user_input',
        data: {
          message,
          attachments: attachments.map(a => ({ id: a.id, name: a.name, size: a.size, type: a.type })),
        },
      }));
      setIsExecuting(true);
    }
  }, [setIsExecuting]);

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
    sendUserInput,
    sendInterrupt,
  };
}

// 导出配置供测试使用
export { wsHook };