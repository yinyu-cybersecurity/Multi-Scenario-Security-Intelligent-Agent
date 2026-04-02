// frontend/src/components/DetailPanel/DetailPanel.tsx

import React from 'react';
import clsx from 'clsx';
import { Wrench, Search, Flag, ChevronRight } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';
import { ToolCard } from './ToolCard';
import { FindingCard } from './FindingCard';
import { FlagCard } from './FlagCard';

export const DetailPanel: React.FC = () => {
  const {
    toolExecutions,
    findings,
    flags,
    detailPanelCollapsed,
    detailPanelTab,
    setDetailPanelCollapsed,
    setDetailPanelTab,
    setSelectedLogEntry,
  } = useAppStore();

  const handleToolClick = (toolId: string) => {
    // Scroll log to this tool
    setSelectedLogEntry(toolId);
  };

  const handleFindingClick = (findingId: string) => {
    setSelectedLogEntry(findingId);
  };

  if (detailPanelCollapsed) {
    return (
      <div className="w-10 h-full bg-secondary border-l border-border flex flex-col items-center py-2 gap-2">
        <button
          className={clsx(
            'p-2 rounded cursor-pointer',
            detailPanelTab === 'tools' ? 'bg-blue-500/20 text-blue-500' : 'text-muted-foreground hover:bg-muted'
          )}
          onClick={() => {
            setDetailPanelTab('tools');
            setDetailPanelCollapsed(false);
          }}
          title="Tools"
        >
          <Wrench className="w-4 h-4" />
        </button>
        <button
          className={clsx(
            'p-2 rounded cursor-pointer',
            detailPanelTab === 'findings' ? 'bg-blue-500/20 text-blue-500' : 'text-muted-foreground hover:bg-muted'
          )}
          onClick={() => {
            setDetailPanelTab('findings');
            setDetailPanelCollapsed(false);
          }}
          title="Findings"
        >
          <Search className="w-4 h-4" />
        </button>
        <button
          className={clsx(
            'p-2 rounded cursor-pointer',
            detailPanelTab === 'flags' ? 'bg-blue-500/20 text-blue-500' : 'text-muted-foreground hover:bg-muted'
          )}
          onClick={() => {
            setDetailPanelTab('flags');
            setDetailPanelCollapsed(false);
          }}
          title="Flags"
        >
          <Flag className="w-4 h-4" />
        </button>
      </div>
    );
  }

  return (
    <div className="w-[300px] h-full bg-secondary border-l border-border flex flex-col">
      {/* Tabs */}
      <div className="flex border-b border-border bg-muted/50">
        <button
          className={clsx(
            'flex-1 py-2.5 text-center text-xs font-medium border-b-2 transition-colors',
            detailPanelTab === 'tools'
              ? 'text-foreground border-blue-500'
              : 'text-muted-foreground border-transparent hover:text-foreground'
          )}
          onClick={() => setDetailPanelTab('tools')}
        >
          Tools
          {toolExecutions.length > 0 && (
            <span className="ml-1 px-1 bg-primary rounded text-[10px]">
              {toolExecutions.length}
            </span>
          )}
        </button>
        <button
          className={clsx(
            'flex-1 py-2.5 text-center text-xs font-medium border-b-2 transition-colors',
            detailPanelTab === 'findings'
              ? 'text-foreground border-blue-500'
              : 'text-muted-foreground border-transparent hover:text-foreground'
          )}
          onClick={() => setDetailPanelTab('findings')}
        >
          Findings
          {findings.length > 0 && (
            <span className="ml-1 px-1 bg-primary rounded text-[10px]">
              {findings.length}
            </span>
          )}
        </button>
        <button
          className={clsx(
            'flex-1 py-2.5 text-center text-xs font-medium border-b-2 transition-colors',
            detailPanelTab === 'flags'
              ? 'text-foreground border-blue-500'
              : 'text-muted-foreground border-transparent hover:text-foreground'
          )}
          onClick={() => setDetailPanelTab('flags')}
        >
          Flags
          {flags.length > 0 && (
            <span className="ml-1 px-1 bg-primary rounded text-[10px]">
              {flags.length}
            </span>
          )}
        </button>
        <button
          className="p-2 hover:bg-muted"
          onClick={() => setDetailPanelCollapsed(true)}
          title="Collapse"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-3">
        {detailPanelTab === 'tools' && (
          toolExecutions.length === 0 ? (
            <div className="text-center text-muted-foreground text-xs py-8">
              No tool executions yet
            </div>
          ) : (
            toolExecutions
              .slice()
              .reverse()
              .map((tool) => (
                <ToolCard
                  key={tool.id}
                  tool={tool}
                  onClick={() => handleToolClick(tool.id)}
                />
              ))
          )
        )}

        {detailPanelTab === 'findings' && (
          findings.length === 0 ? (
            <div className="text-center text-muted-foreground text-xs py-8">
              No findings yet
            </div>
          ) : (
            findings
              .slice()
              .reverse()
              .map((finding) => (
                <FindingCard
                  key={finding.id}
                  finding={finding}
                  onClick={() => handleFindingClick(finding.id)}
                />
              ))
          )
        )}

        {detailPanelTab === 'flags' && (
          flags.length === 0 ? (
            <div className="text-center text-muted-foreground text-xs py-8">
              No flags found yet
            </div>
          ) : (
            flags.map((flag) => <FlagCard key={flag.id} flag={flag} />)
          )
        )}
      </div>
    </div>
  );
};