// frontend/src/components/Chat/InputBar.tsx

import React, { useRef, useCallback, useEffect } from 'react';
import { Paperclip } from 'lucide-react';
import { useChatState, useChatActions, useIsExecuting } from '../../store/useAppStore';
import { useFileUpload } from '../../hooks/useFileUpload';
import { useWebSocket } from '../../hooks/useWebSocket';

export const InputBar: React.FC = () => {
  // 使用细粒度选择器，避免不必要重渲染
  const { inputValue, attachments, isDragging } = useChatState();
  const isExecuting = useIsExecuting();
  const { setInputValue, addLogEntry, clearAttachments } = useChatActions();

  const { sendUserInput, sendInterrupt } = useWebSocket();
  const { handleDrop, handleDragOver, handleDragLeave, handleFileSelect } = useFileUpload();
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSend = useCallback(() => {
    const message = inputValue.trim();
    if (!message && attachments.length === 0) return;
    if (isExecuting) return; // Prevent sending while executing

    // Add user message to log
    addLogEntry({
      id: `user-${Date.now()}`,
      timestamp: new Date(),
      type: 'info',
      message: `[User] ${message}`,
      iteration: 0,
      node: 'think',
    });

    // Log attachments if any
    if (attachments.length > 0) {
      attachments.forEach((a) => {
        addLogEntry({
          id: `file-${Date.now()}-${a.id}`,
          timestamp: new Date(),
          type: 'info',
          message: `[File] ${a.name} uploaded`,
          iteration: 0,
          node: 'think',
        });
      });
    }

    // Send to backend via WebSocket
    sendUserInput(message, attachments);

    // Clear input
    setInputValue('');
    clearAttachments();

    // Reset textarea height
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
  }, [inputValue, attachments, isExecuting, addLogEntry, setInputValue, clearAttachments, sendUserInput]);

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
        addLogEntry({
          id: `interrupt-${Date.now()}`,
          timestamp: new Date(),
          type: 'info',
          message: '[System] Execution interrupted',
          iteration: 0,
          node: 'think',
        });
        sendInterrupt(); // Notify backend
      }
    };

    window.addEventListener('keydown', handleCtrlC);
    return () => window.removeEventListener('keydown', handleCtrlC);
  }, [isExecuting, addLogEntry, sendInterrupt]);

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

      <button
        onClick={() => fileInputRef.current?.click()}
        className="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded transition-colors flex-shrink-0"
        title="Upload files"
      >
        <Paperclip className="w-5 h-5" />
      </button>

      <textarea
        ref={textareaRef}
        value={inputValue}
        onChange={(e) => {
          setInputValue(e.target.value);
          adjustTextareaHeight();
        }}
        onKeyDown={handleKeyDown}
        placeholder=""
        className="flex-1 bg-background border border-border rounded px-3 py-2 text-sm resize-none focus:outline-none focus:ring-1 focus:ring-primary min-h-[40px]"
        rows={1}
        style={{ maxHeight: '72px' }}
      />
    </div>
  );
};