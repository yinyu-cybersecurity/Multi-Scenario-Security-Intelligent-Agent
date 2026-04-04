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
    const msgKey = `${lastMessage.type}-${JSON.stringify(lastMessage)}`;
    if (lastProcessedRef.current === msgKey) return;
    lastProcessedRef.current = msgKey;

    // 处理消息
    processWSMessage(lastMessage, store);
  }, [lastMessage, store]);
}

/**
 * 处理WebSocket消息 - 极简推导逻辑
 */
function processWSMessage(msg: WSMessage, store: ReturnType<typeof useConsoleStore.getState>) {
  switch (msg.type) {
    // ================================
    // 基础事件推导
    // ================================

    case 'assistant_message': {
      const { content, turn } = msg;

      // 推导迭代
      if (turn) {
        store.setCurrentIteration(turn);
      }

      // 添加AI消息到控制台
      store.addAssistantMessage(content || '', false, turn);

      // 推导Flag（正则提取）
      const flagMatches = content?.match(/flag\{[^}]+\}/gi) || [];
      flagMatches.forEach((flagValue: string) => {
        store.addSystemMessage(`🚩 发现Flag: ${flagValue}`);
      });

      break;
    }

    case 'tool_result': {
      const { tool_name } = msg;

      // 推导工具调用
      const toolId = store.startToolCall({
        toolName: tool_name || 'unknown',
        iteration: store.currentIteration,
      });

      // 立即完成（后端不发送tool_start）
      store.completeToolCall(toolId, 'Tool executed successfully', 0);

      break;
    }

    case 'complete': {
      const { reason } = msg;

      // 推导任务完成状态
      store.addSystemMessage(`任务结束: ${reason || '未知原因'}`);

      break;
    }

    case 'loop_detected': {
      const { tool } = msg;

      store.addSystemMessage(`⚠️ 检测到循环调用: ${tool}`);

      break;
    }

    // ================================
    // 其他事件保持兼容
    // ================================

    case 'connection_established':
      store.addSystemMessage('Connected to CTF-Agent 2.0');
      break;

    case 'interrupt':
      store.addSystemMessage(`Task interrupted: ${msg.data?.reason || 'user cancel'}`);
      break;

    default:
      // 忽略其他消息类型
      break;
  }
}

export default useConsoleEventProcessor;