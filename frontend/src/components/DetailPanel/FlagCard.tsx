// frontend/src/components/DetailPanel/FlagCard.tsx

import React from 'react';
import { Flag, Copy, Check } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';
import type { Flag as FlagType } from '../../store/types';

interface FlagCardProps {
  flag: FlagType;
}

export const FlagCard: React.FC<FlagCardProps> = ({ flag }) => {
  const { setFlagCopied } = useAppStore();

  const handleCopy = () => {
    navigator.clipboard.writeText(flag.value);
    setFlagCopied(flag.id, true);
  };

  return (
    <div className="bg-secondary border border-border rounded-md p-3 mb-2 border-l-2 border-l-green-500">
      <div className="flex items-center gap-2 text-green-500 mb-2">
        <Flag className="w-4 h-4" />
        <span className="text-xs font-semibold">Flag Found</span>
      </div>

      <div className="font-mono text-sm bg-primary/30 p-3 rounded border border-green-500/30 text-green-400 break-all">
        {flag.value}
      </div>

      <div className="flex gap-2 mt-2">
        <button
          className="text-[10px] px-2 py-1 bg-muted rounded border border-border hover:bg-secondary"
          onClick={handleCopy}
        >
          {flag.copied ? (
            <>
              <Check className="w-3 h-3 inline mr-1" />
              Copied
            </>
          ) : (
            <>
              <Copy className="w-3 h-3 inline mr-1" />
              Copy
            </>
          )}
        </button>
      </div>
    </div>
  );
};