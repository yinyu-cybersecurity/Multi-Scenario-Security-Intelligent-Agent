// frontend/src/App.tsx

import { BrowserRouter, Routes, Route } from 'react-router-dom';

// Components
import { Header } from './components/common/Header';
import { StatsBar } from './components/common/StatsBar';
import { Timeline } from './components/Timeline/Timeline';
import { LogStream } from './components/LogStream/LogStream';
import { DetailPanel } from './components/DetailPanel/DetailPanel';

function Dashboard() {
  return (
    <div className="flex flex-col h-screen bg-background text-foreground">
      {/* Header */}
      <Header />

      {/* Stats Bar */}
      <StatsBar />

      {/* Main Content - Three Column Layout */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: Timeline */}
        <Timeline />

        {/* Center: Log Stream */}
        <LogStream />

        {/* Right: Detail Panel */}
        <DetailPanel />
      </div>
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