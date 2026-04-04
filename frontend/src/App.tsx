// frontend/src/App.tsx

import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { useEffect } from 'react';

// Components
import { Header } from './components/common/Header';
import { StatsBar } from './components/common/StatsBar';
import { Timeline } from './components/Timeline/Timeline';
import { ConsoleStream } from './components/Console/ConsoleStream';
import { DetailPanel } from './components/DetailPanel/DetailPanel';
import { AttachmentBar } from './components/Chat/AttachmentBar';
import { InputBar } from './components/Chat/InputBar';

// Hooks
import { useWebSocket } from './hooks/useWebSocket';
import { useConsoleEventProcessor } from './hooks/useConsoleEventProcessor';
import { useAppStore } from './store/useAppStore';

function Dashboard() {
  // 初始化WebSocket
  const { sendInterrupt } = useWebSocket();

  // 处理控制台事件
  useConsoleEventProcessor();

  // 获取状态和方法
  const { isExecuting, setIsExecuting } = useAppStore();

  // 全局快捷键
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ctrl+L: 清空控制台（使用consoleStore）
      if (e.ctrlKey && e.key === 'l') {
        e.preventDefault();
        // 清空控制台由consoleStore处理
        console.log('Clear console');
      }

      // Ctrl+S: 停止执行
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        if (isExecuting) {
          sendInterrupt();
          setIsExecuting(false);
        }
      }

      // Ctrl+R: 重新开始（刷新页面）
      if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        if (window.confirm('确定要重新开始吗？这将清空所有状态。')) {
          window.location.reload();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isExecuting, sendInterrupt, setIsExecuting]);

  return (
    <div className="flex flex-col h-screen bg-background text-foreground">
      {/* Header */}
      <Header />

      {/* Stats Bar */}
      <StatsBar />

      {/* Main Content - Three Column Layout */}
      <div className="flex flex-1 overflow-hidden min-h-0">
        {/* Left: Timeline */}
        <Timeline />

        {/* Center: Console Stream (New) */}
        <ConsoleStream />

        {/* Right: Detail Panel */}
        <DetailPanel />
      </div>

      {/* Attachment Bar */}
      <AttachmentBar />

      {/* Input Bar */}
      <InputBar />
    </div>
  );
}

function SettingsPage() {
  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-4">Settings</h1>
      <div className="bg-secondary rounded-lg p-6 border border-border">
        <p className="text-muted-foreground">Settings page coming soon.</p>
      </div>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;