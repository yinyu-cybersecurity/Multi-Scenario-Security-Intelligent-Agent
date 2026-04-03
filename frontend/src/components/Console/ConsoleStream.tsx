// frontend/src/components/Console/ConsoleStream.tsx
/**
 * 控制台消息流 - 完全复刻Claude Code布局
 *
 * 特性:
 * - 消息列表渲染
 * - 自动滚动
 * - 搜索过滤
 * - 迭代分隔线
 * - 键盘快捷键
 */

import React, { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowDown, Search } from 'lucide-react';
import { useConsoleStore } from '../../store/consoleStore';
import { ConsoleMessageRenderer } from './MessageRenderer';

export const ConsoleStream: React.FC = () => {
  const {
    messages,
    autoScroll,
    searchFilter,
    setAutoScroll,
    setSearchFilter,
  } = useConsoleStore();

  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // 自动滚动
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [messages, autoScroll]);

  // 检测用户滚动
  const handleScroll = () => {
    if (containerRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
      const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
      setAutoScroll(isAtBottom);
    }
  };

  // 键盘快捷键 Ctrl+F
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'f') {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // 过滤消息
  const filteredMessages = searchFilter
    ? messages.filter(msg => {
        if (msg.type === 'tool_call') {
          return (msg.toolName + (msg.command || '')).toLowerCase().includes(searchFilter.toLowerCase());
        }
        if (msg.type === 'user' || msg.type === 'assistant') {
          return msg.content.toLowerCase().includes(searchFilter.toLowerCase());
        }
        if (msg.type === 'error') {
          return msg.content.toLowerCase().includes(searchFilter.toLowerCase());
        }
        return true;
      })
    : messages;

  // 跳转最新
  const jumpToLatest = () => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
      setAutoScroll(true);
    }
  };

  return (
    <div
      ref={containerRef}
      className="console-stream flex-1 h-full bg-background font-mono text-xs leading-relaxed overflow-y-auto"
      onScroll={handleScroll}
    >
      {/* 搜索栏 */}
      <div className="sticky top-0 bg-background p-2 border-b border-border z-10">
        <div className="relative">
          <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Search messages... (Ctrl+F)"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="w-full bg-secondary border border-border rounded pl-8 pr-2 py-1.5 text-xs text-foreground outline-none focus:border-blue-500"
          />
        </div>
      </div>

      {/* 消息列表 */}
      <div className="px-2 py-2">
        <AnimatePresence mode="popLayout">
          {filteredMessages.map((message) => (
            <motion.div
              key={message.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
            >
              <ConsoleMessageRenderer message={message} />
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {/* 空状态 */}
      {filteredMessages.length === 0 && (
        <div className="text-center text-muted-foreground py-12">
          {searchFilter ? 'No matching messages found' : 'Console ready. Enter a task to begin.'}
        </div>
      )}

      {/* 跳转最新按钮 */}
      {!autoScroll && (
        <button
          className="sticky bottom-4 left-1/2 -translate-x-1/2 bg-secondary border border-border rounded-full px-3 py-1.5 text-xs cursor-pointer text-foreground shadow-lg hover:bg-muted flex items-center gap-1"
          onClick={jumpToLatest}
        >
          <ArrowDown size={14} />
          Jump to latest
        </button>
      )}
    </div>
  );
};

export default ConsoleStream;