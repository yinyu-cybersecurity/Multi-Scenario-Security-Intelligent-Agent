// frontend/src/components/Chat/AttachmentBar.tsx

import React from 'react';
import { X } from 'lucide-react';
import { useFileUpload } from '../../hooks/useFileUpload';

export const AttachmentBar: React.FC = () => {
  const { attachments, removeAttachment, formatSize } = useFileUpload();

  if (attachments.length === 0) {
    return null;
  }

  return (
    <div className="flex items-center gap-2 px-4 py-2 bg-secondary border-t border-border overflow-x-auto">
      {attachments.map((attachment) => (
        <div
          key={attachment.id}
          className="flex items-center gap-1 px-2 py-1 bg-muted rounded text-xs whitespace-nowrap"
        >
          <span className="text-foreground">{attachment.name}</span>
          <span className="text-muted-foreground">({formatSize(attachment.size)})</span>
          <button
            onClick={() => removeAttachment(attachment.id)}
            className="ml-1 text-muted-foreground hover:text-foreground"
          >
            <X className="w-3 h-3" />
          </button>
        </div>
      ))}
    </div>
  );
};