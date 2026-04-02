// frontend/src/components/LogStream/LogStream.tsx

import React, { useEffect, useRef, useState } from 'react';
import { useAppStore } from '../../store/useAppStore';
import { LogEntryComponent, LogSeparator } from './LogEntry';
import { ArrowDown } from 'lucide-react';

export const LogStream: React.FC = () => {
  const { logEntries, selectedLogEntryId, setSelectedLogEntry } = useAppStore();
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  // Auto-scroll to bottom when new entries arrive
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logEntries, autoScroll]);

  // Handle scroll to detect if user scrolled up
  const handleScroll = () => {
    if (containerRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
      const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
      setAutoScroll(isAtBottom);
    }
  };

  // Jump to latest
  const jumpToLatest = () => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
      setAutoScroll(true);
    }
  };

  // Filter logs by search term
  const filteredEntries = searchTerm
    ? logEntries.filter((entry) =>
        entry.message.toLowerCase().includes(searchTerm.toLowerCase())
      )
    : logEntries;

  return (
    <div
      ref={containerRef}
      className="flex-1 h-full bg-background font-mono text-xs leading-relaxed overflow-y-auto p-4"
      onScroll={handleScroll}
    >
      {/* Search bar */}
      <div className="sticky top-0 bg-background p-2 border-b border-border -mx-4 -mt-4 mb-4 z-10">
        <input
          type="text"
          placeholder="Search logs... (Ctrl+F)"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full bg-secondary border border-border rounded px-2 py-1 text-xs text-foreground outline-none focus:border-blue-500"
        />
      </div>

      {/* Log entries */}
      {filteredEntries.map((entry, index) => {
        const showSeparator =
          index === 0 ||
          entry.iteration !== filteredEntries[index - 1].iteration;

        return (
          <React.Fragment key={entry.id}>
            {showSeparator && <LogSeparator timestamp={entry.timestamp} />}
            <LogEntryComponent
              entry={entry}
              isSelected={entry.id === selectedLogEntryId}
              onClick={() => setSelectedLogEntry(entry.id)}
            />
          </React.Fragment>
        );
      })}

      {/* Empty state */}
      {filteredEntries.length === 0 && (
        <div className="text-center text-muted-foreground py-8">
          {searchTerm ? 'No matching logs found' : 'No logs yet. Start a task to begin.'}
        </div>
      )}

      {/* Jump to latest button */}
      {!autoScroll && (
        <button
          className="sticky bottom-4 left-1/2 -translate-x-1/2 bg-secondary border border-border rounded px-3 py-1 text-xs cursor-pointer text-foreground shadow-lg hover:bg-muted"
          onClick={jumpToLatest}
        >
          <ArrowDown className="w-3 h-3 inline mr-1" />
          Jump to latest
        </button>
      )}
    </div>
  );
};