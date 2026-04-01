import React from 'react';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import { useAppStore } from '@/store/useAppStore';
import { AgentStatusCard } from '@/components/AgentStatusCard';
import { Activity, Target, Shield, CheckCircle, Settings, Flag } from 'lucide-react';

function Dashboard() {
  const { currentTask, flags, findings, wsConnected } = useAppStore();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">CTF-Agent Dashboard</h1>
          <p className="text-muted-foreground">
            {currentTask ? `Task: ${currentTask.title}` : 'No active task'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-xs text-muted-foreground">
            {wsConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-secondary rounded-lg p-4 border border-border">
          <div className="flex items-center gap-2 text-muted-foreground">
            <Target className="w-4 h-4" />
            <span className="text-xs">Findings</span>
          </div>
          <p className="text-2xl font-bold mt-2">{findings.length}</p>
        </div>

        <div className="bg-secondary rounded-lg p-4 border border-border">
          <div className="flex items-center gap-2 text-muted-foreground">
            <Flag className="w-4 h-4" />
            <span className="text-xs">Flags</span>
          </div>
          <p className="text-2xl font-bold mt-2 text-green-500">{flags.length}</p>
        </div>

        <div className="bg-secondary rounded-lg p-4 border border-border">
          <div className="flex items-center gap-2 text-muted-foreground">
            <Activity className="w-4 h-4" />
            <span className="text-xs">Tools</span>
          </div>
          <p className="text-2xl font-bold mt-2">12</p>
        </div>

        <div className="bg-secondary rounded-lg p-4 border border-border">
          <div className="flex items-center gap-2 text-muted-foreground">
            <Shield className="w-4 h-4" />
            <span className="text-xs">Skills</span>
          </div>
          <p className="text-2xl font-bold mt-2">8</p>
        </div>
      </div>

      {/* Agents */}
      <div>
        <h2 className="text-lg font-semibold mb-4">Agent Status</h2>
        <div className="grid grid-cols-2 gap-4">
          <AgentStatusCard agentType="explore" />
          <AgentStatusCard agentType="plan" />
          <AgentStatusCard agentType="attack" />
          <AgentStatusCard agentType="verify" />
        </div>
      </div>

      {/* Recent Findings */}
      {findings.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-4">Recent Findings</h2>
          <div className="space-y-2">
            {findings.slice(-5).map((finding) => (
              <div
                key={finding.id}
                className="bg-secondary rounded-lg p-3 border border-border"
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{finding.title}</span>
                  <span
                    className={`text-xs px-2 py-0.5 rounded ${
                      finding.severity === 'critical'
                        ? 'bg-red-500/20 text-red-500'
                        : finding.severity === 'high'
                        ? 'bg-orange-500/20 text-orange-500'
                        : finding.severity === 'medium'
                        ? 'bg-yellow-500/20 text-yellow-500'
                        : 'bg-blue-500/20 text-blue-500'
                    }`}
                  >
                    {finding.severity}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mt-1 truncate">
                  {finding.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-background text-foreground">
        {/* Sidebar */}
        <div className="fixed left-0 top-0 w-64 h-screen bg-secondary border-r border-border p-4">
          <div className="flex items-center gap-2 mb-8">
            <Shield className="w-6 h-6 text-primary" />
            <span className="text-lg font-bold">CTF-Agent</span>
          </div>

          <nav className="space-y-2">
            <Link
              to="/"
              className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-muted transition-colors"
            >
              <Activity className="w-4 h-4" />
              <span className="text-sm">Dashboard</span>
            </Link>
            <Link
              to="/settings"
              className="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-muted transition-colors"
            >
              <Settings className="w-4 h-4" />
              <span className="text-sm">Settings</span>
            </Link>
          </nav>

          <div className="absolute bottom-4 left-4 right-4">
            <div className="bg-muted rounded-lg p-3">
              <p className="text-xs text-muted-foreground">Version 2.0</p>
              <p className="text-xs text-muted-foreground">Phase 2 Complete</p>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="ml-64 p-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/settings" element={<div>Settings Page (Coming Soon)</div>} />
          </Routes>
        </div>
      </div>
    </BrowserRouter>
  );
}

export default App;