// frontend/src/components/Chat/InputBar.tsx

import React, { useRef, useCallback, useEffect } from 'react';
import { Paperclip, Square, Loader2 } from 'lucide-react';
import { useChatState, useChatActions, useIsExecuting } from '../../store/useAppStore';
import { useFileUpload } from '../../hooks/useFileUpload';
import { useWebSocket } from '../../hooks/useWebSocket';

export const InputBar: React.FC = () => {
  // 使用细粒度选择器，避免不必要重渲染
  const { inputValue, attachments, isDragging } = useChatState();
  const isExecuting = useIsExecuting();
  const { setInputValue, addLogEntry, clearAttachments } = useChatActions();

  const { sendUserInput, sendInterrupt, sendStart } = useWebSocket();
  const { handleDrop, handleDragOver, handleDragLeave, handleFileSelect } = useFileUpload();
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSend = useCallback(() => {
    const message = inputValue.trim();
    if (!message && attachments.length === 0) return;

    // 检查是否是启动命令
    if (message.startsWith('target ') || message.startsWith('http')) {
      const target = message.startsWith('target ') ? message.slice(7).trim() : message.trim();

      addLogEntry({
        id: `user-${Date.now()}`,
        timestamp: new Date(),
        type: 'info',
        message: `[User] Starting task: ${target}`,
        iteration: 0,
        node: 'think',
      });

      sendStart(target);
      setInputValue('');
      return;
    }

    // 普通消息
    if (isExecuting) {
      // 执行中发送的是反馈
      addLogEntry({
        id: `user-${Date.now()}`,
        timestamp: new Date(),
        type: 'info',
        message: `[User Feedback] ${message}`,
        iteration: 0,
        node: 'think',
      });
      sendUserInput(message, []);
    } else {
      // 未执行时发送的是目标
      addLogEntry({
        id: `user-${Date.now()}`,
        timestamp: new Date(),
        type: 'info',
        message: `[User] ${message}`,
        iteration: 0,
        node: 'think',
      });
      sendUserInput(message, attachments);
    }

    // Clear input
    setInputValue('');
    clearAttachments();

    // Reset textarea height
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
  }, [inputValue, attachments, isExecuting, addLogEntry, setInputValue, clearAttachments, sendUserInput, sendStart]);

  const handleStop = useCallback(() => {
    addLogEntry({
      id: `interrupt-${Date.now()}`,
      timestamp: new Date(),
      type: 'info',
      message: '[System] ⚠️ Execution interrupted by user',
      iteration: 0,
      node: 'think',
    });
    sendInterrupt();
  }, [addLogEntry, sendInterrupt]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }, [handleSend]);

  // Handle Ctrl+C to interrupt - notify backend
  useEffect(() => {
    const handleCtrlC = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'c' && isExecuting) {
        e.preventDefault();
        handleStop();
      }
    };

    window.addEventListener('keydown', handleCtrlC);
    return () => window.removeEventListener('keydown', handleCtrlC);
  }, [isExecuting, handleStop]);

  const adjustTextareaHeight = useCallback(() => {
    const textarea = textareaRef.current;
    if (textarea) {
      textarea.style.height = 'auto';
      textarea.style.height = `${Math.min(textarea.scrollHeight, 72)}px`;
    }
  }, []);

  return (
    <div
      className={`flex items-end gap-2 p-4 bg-secondary border-t border-border transition-colors ${
        isDragging ? 'border-t-2 border-t-blue-500 bg-blue-500/5' : ''
      }`}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
    >
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={handleFileSelect}
      />

      {/* 文件上传按钮 - 仅非执行时显示 */}
      {!isExecuting && (
        <button
          onClick={() => fileInputRef.current?.click()}
          className="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded transition-colors flex-shrink-0"
          title="Upload files"
        >
          <Paperclip className="w-5 h-5" />
        </button>
      )}

      {/* 状态指示器 */}
      {isExecuting && (
        <div className="flex items-center gap-2 px-3 py-1 bg-blue-500/20 text-blue-500 rounded-full text-xs">
          <Loader2 className="w-3 h-3 animate-spin" />
          Running
        </div>
      )}

      <textarea
        ref={textareaRef}
        value={inputValue}
        onChange={(e) => {
          setInputValue(e.target.value);
          adjustTextareaHeight();
        }}
        onKeyDown={handleKeyDown}
        placeholder={isExecuting ? "Type feedback or press Stop button to interrupt..." : "target <url> or http://... to start"}
        className="flex-1 bg-background border border-border rounded px-3 py-2 text-sm resize-none focus:outline-none focus:ring-1 focus:ring-primary min-h-[40px]"
        rows={1}
        style={{ maxHeight: '72px' }}
      />

      {/* 发送/停止按钮 */}
      {isExecuting ? (
        <button
          onClick={handleStop}
          className="px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600 transition-colors flex items-center gap-2 flex-shrink-0"
          title="Stop execution (or Ctrl+C)"
        >
          <Square className="w-4 h-4" />
          Stop
        </button>
      ) : (
        <button
          onClick={handleSend}
          disabled={!inputValue.trim() && attachments.length === 0}
          className="px-4 py-2 bg-primary text-primary-foreground rounded hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex-shrink-0"
        >
          Send
        </button>
      )}
    </div>
  );
};