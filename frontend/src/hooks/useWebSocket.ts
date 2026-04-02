// frontend/src/hooks/useWebSocket.ts

import { useEffect, useRef, useCallback } from 'react';
import { useAppStore } from '../store/useAppStore';
import type { WSMessage, NodeType, LogEntry, ToolExecution, Finding, Flag, Iteration, Attachment } from '../store/types';

const WS_URL = 'ws://localhost:8000/ws';

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

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

  const handleMessage = useCallback((event: MessageEvent) => {
    try {
      const message: WSMessage = JSON.parse(event.data);

      switch (message.type) {
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
            timestamp: new Date(message.data.timestamp),
          } as LogEntry);
          break;
        }

        case 'tool_start': {
          addToolExecution({
            ...message.data,
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
            timestamp: new Date(message.data.timestamp),
          } as Finding);
          break;
        }

        case 'flag': {
          addFlag({
            ...message.data,
            timestamp: new Date(message.data.timestamp),
          } as Flag);
          break;
        }

        case 'iteration_end': {
          const { iteration } = message.data;
          addLogEntry({
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
            timestamp: new Date(),
            type: 'info',
            message: `[File] Uploaded: ${filename} (${sizeStr})`,
            iteration: 0,
            node: 'think',
          } as LogEntry);
          break;
        }

        case 'execution_status': {
          const { isExecuting, task } = message.data;
          setIsExecuting(isExecuting);
          if (isExecuting && task) {
            addLogEntry({
              timestamp: new Date(),
              type: 'info',
              message: `[System] Task started: ${task}`,
              iteration: 0,
              node: 'think',
            } as LogEntry);
          }
          break;
        }
      }
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error);
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

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsConnected(true);
      console.log('WebSocket connected');
    };

    ws.onmessage = handleMessage;

    ws.onclose = () => {
      setWsConnected(false);
      console.log('WebSocket disconnected');

      // Reconnect after 3 seconds
      reconnectTimeoutRef.current = window.setTimeout(() => {
        connect();
      }, 3000);
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }, [setWsConnected, handleMessage]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    wsRef.current?.close();
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
    isConnected: wsRef.current?.readyState === WebSocket.OPEN,
    connect,
    disconnect,
    sendUserInput,
    sendInterrupt,
  };
}