// frontend/src/components/common/Header.tsx

import React from 'react';
import { Shield, Wifi, WifiOff, Settings } from 'lucide-react';
import { useAppStore } from '../../store/useAppStore';

export const Header: React.FC = () => {
  const { currentTask, wsConnected } = useAppStore();

  return (
    <header className="flex items-center justify-between px-6 py-4 border-b border-border bg-secondary">
      <div className="flex items-center gap-3">
        <Shield className="w-6 h-6 text-primary" />
        <div>
          <h1 className="text-lg font-bold">CTF-Agent 2.0 Dashboard</h1>
          {currentTask && (
            <p className="text-xs text-muted-foreground">
              {currentTask.description || currentTask.target}
            </p>
          )}
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* WebSocket status */}
        <div className="flex items-center gap-2">
          {wsConnected ? (
            <>
              <Wifi className="w-4 h-4 text-green-500" />
              <span className="text-xs text-green-500">Connected</span>
            </>
          ) : (
            <>
              <WifiOff className="w-4 h-4 text-red-500" />
              <span className="text-xs text-red-500">Disconnected</span>
            </>
          )}
        </div>

        {/* Settings button */}
        <button className="p-2 hover:bg-muted rounded">
          <Settings className="w-4 h-4 text-muted-foreground" />
        </button>
      </div>
    </header>
  );
};