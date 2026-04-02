// frontend/src/components/DetailPanel/FindingCard.tsx

import React from 'react';
import clsx from 'clsx';
import { AlertTriangle, ExternalLink, Copy } from 'lucide-react';
import type { Finding } from '../../store/types';

interface FindingCardProps {
  finding: Finding;
  onClick: () => void;
}

const severityLabels = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

const severityColors = {
  critical: 'text-red-500 bg-red-500/10',
  high: 'text-orange-500 bg-orange-500/10',
  medium: 'text-yellow-500 bg-yellow-500/10',
  low: 'text-blue-500 bg-blue-500/10',
};

const severityBorders = {
  critical: 'border-l-red-500',
  high: 'border-l-orange-500',
  medium: 'border-l-yellow-500',
  low: 'border-l-blue-500',
};

export const FindingCard: React.FC<FindingCardProps> = ({ finding, onClick }) => {
  return (
    <div
      className={clsx(
        'bg-secondary border border-border rounded-md p-3 mb-2 cursor-pointer hover:bg-muted transition-colors border-l-2',
        severityBorders[finding.severity]
      )}
      onClick={onClick}
    >
      <div className="flex items-center gap-2 mb-2">
        <AlertTriangle className="w-3 h-3" />
        <span className={clsx('text-[10px] px-1.5 py-0.5 rounded', severityColors[finding.severity])}>
          {severityLabels[finding.severity]}
        </span>
      </div>

      <div className="text-xs font-semibold mb-1">{finding.title}</div>

      <div className="text-xs text-muted-foreground">
        <div className="mb-2">{finding.description}</div>

        {finding.evidence && (
          <div className="font-mono bg-primary/30 p-2 rounded truncate">
            {finding.evidence}
          </div>
        )}
      </div>

      <div className="flex gap-2 mt-2">
        <button className="text-[10px] px-2 py-1 bg-muted rounded border border-border hover:bg-secondary">
          <ExternalLink className="w-3 h-3 inline mr-1" />
          Details
        </button>
        {finding.evidence && (
          <button
            className="text-[10px] px-2 py-1 bg-muted rounded border border-border hover:bg-secondary"
            onClick={(e) => {
              e.stopPropagation();
              navigator.clipboard.writeText(finding.evidence || '');
            }}
          >
            <Copy className="w-3 h-3 inline mr-1" />
            Copy
          </button>
        )}
      </div>
    </div>
  );
};