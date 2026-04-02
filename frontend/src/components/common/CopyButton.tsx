// frontend/src/components/common/CopyButton.tsx

import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface CopyButtonProps {
  text: string;
  className?: string;
}

export const CopyButton: React.FC<CopyButtonProps> = ({ text, className = '' }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className={`px-2 py-1 text-xs rounded border border-border hover:bg-muted transition-colors ${className}`}
    >
      {copied ? (
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
  );
};