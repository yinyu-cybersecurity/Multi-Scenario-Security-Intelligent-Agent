// frontend/src/components/Console/MessageRenderer.tsx
/**
 * 消息渲染器 - 根据消息类型选择组件
 */

import React from 'react';
import type { ConsoleMessage } from '../../store/consoleTypes';
import { ToolCallCard } from './ToolCallCard';
import { UserMessageView } from './UserMessageView';
import { AssistantMessageView } from './AssistantMessageView';
import { ErrorMessageView } from './ErrorMessageView';
import { SystemMessageView } from './SystemMessageView';
import { SeparatorLine } from './SeparatorLine';
import { useConsoleStore } from '../../store/consoleStore';

/**
 * 消息类型渲染器
 */
export const ConsoleMessageRenderer: React.FC<{
  message: ConsoleMessage;
}> = ({ message }) => {
  const toggleExpand = useConsoleStore(state => state.toggleExpand);

  switch (message.type) {
    case 'user':
      return <UserMessageView message={message} />;

    case 'assistant':
      return <AssistantMessageView message={message} />;

    case 'tool_call':
      return (
        <ToolCallCard
          message={message}
          onToggle={() => toggleExpand(message.id)}
        />
      );

    case 'error':
      return <ErrorMessageView message={message} />;

    case 'system':
      return <SystemMessageView message={message} />;

    case 'separator':
      return <SeparatorLine message={message} />;

    default:
      return null;
  }
};

export default ConsoleMessageRenderer;