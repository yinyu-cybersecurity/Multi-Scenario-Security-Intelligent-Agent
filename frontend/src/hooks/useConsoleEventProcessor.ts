// frontend/src/hooks/useConsoleEventProcessor.ts
/**
 * 控制台事件处理器 - 映射WebSocket事件到控制台消息
 *
 * 职责:
 * - 处理后端WebSocket事件
 * - 转换为控制台消息
 * - 更新控制台状态
 */

import { useEffect, useRef } from 'react';
import { useConsoleStore } from '../store/consoleStore';
import { useWSState } from '../store/wsStore';
import type { WSMessage } from '../store/types';

/**
 * 控制台事件处理器Hook
 */
export function useConsoleEventProcessor() {
  const store = useConsoleStore();
  const lastProcessedRef = useRef<string | null>(null);

  // 订阅WebSocket状态
  const lastMessage = useWSState(s => s.lastMessage);

  useEffect(() => {
    if (!lastMessage) return;

    // 避免重复处理
    const msgKey = `${lastMessage.type}-${JSON.stringify(lastMessage.data)}`;
    if (lastProcessedRef.current === msgKey) return;
    lastProcessedRef.current = msgKey;

    // 处理消息
    processWSMessage(lastMessage, store);
  }, [lastMessage, store]);
}

/**
 * 处理WebSocket消息
 */
function processWSMessage(msg: WSMessage, store: ReturnType<typeof useConsoleStore.getState>) {
  switch (msg.type) {
    // ================================
    // 任务事件
    // ================================

    case 'connection_established':
      store.addSystemMessage('Connected to CTF-Agent 2.0');
      break;

    case 'task_start':
      store.clearConsole();
      store.addSystemMessage(`Starting task: ${msg.data.target}`);
      break;

    case 'task_complete':
      if (msg.data.success) {
        store.addSystemMessage(`Task completed. Found ${msg.data.flags?.length || 0} flags.`);
      } else {
        store.addSystemMessage('Task completed without finding flags.');
      }
      break;

    // ================================
    // 迭代事件
    // ================================

    case 'iteration_start':
      store.setCurrentIteration(msg.data.iteration);
      store.addSeparator(msg.data.iteration);
      break;

    case 'iteration_end':
      // 可添加迭代摘要
      break;

    // ================================
    // 节点事件
    // ================================

    case 'node_start':
      // 可添加节点开始指示
      break;

    case 'node_end':
      // 可添加节点完成指示
      break;

    // ================================
    // 工具调用事件 - 核心
    // ================================

    case 'tool_start':
      store.startToolCall({
        toolName: msg.data.toolName || 'Tool',
        command: msg.data.command,
        iteration: msg.data.iteration,
      });
      break;

    case 'tool_complete':
      const output = typeof msg.data.result === 'object'
        ? JSON.stringify(msg.data.result, null, 2)
        : String(msg.data.result || '');
      store.completeToolCall(msg.data.id, output, msg.data.duration || 0);
      break;

    // ================================
    // 日志事件
    // ================================

    case 'log':
      // 根据日志节点类型映射
      const logData = msg.data;
      if (logData.node === 'think') {
        store.addAssistantMessage(logData.message);
      } else if (logData.type === 'error') {
        store.addError(logData.message);
      } else if (logData.type === 'info' || logData.type === 'success') {
        store.addSystemMessage(logData.message);
      }
      break;

    // ================================
    // 发现/Flag事件
    // ================================

    case 'finding':
      store.addSystemMessage(`[Finding] ${msg.data.type}: ${msg.data.title} - ${msg.data.description}`);
      break;

    case 'flag':
      store.addSystemMessage(`🎉 Flag found: ${msg.data.value}`);
      break;

    // ================================
    // 错误/中断事件
    // ================================

    case 'interrupt':
      store.addSystemMessage(`Task interrupted: ${msg.data.reason || 'user cancel'}`);
      break;

    // ================================
    // 文件上传事件
    // ================================

    case 'file_uploaded':
      store.addSystemMessage(`File uploaded: ${msg.data.filename}`);
      break;

    default:
      // 忽略其他消息类型
      break;
  }
}

export default useConsoleEventProcessor;