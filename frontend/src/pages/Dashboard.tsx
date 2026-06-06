import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useSecurityEvents } from '../hooks/useSecurityEvents';
import { SecurityEvent } from '../hooks/useWebSocket';
import { MetricsBar } from '../components/MetricsBar';
import { ThreatFeed } from '../components/ThreatFeed';
import { AgentGrid } from '../components/AgentGrid';
import { TrustGraphViz } from '../components/TrustGraphViz';
import { AttackSimulator } from '../components/AttackSimulator';
import { SelfHealingEngine } from '../components/SelfHealingEngine';
import { SettingsModal } from '../components/SettingsModal';
import { MetricsBarSkeleton, ThreatFeedSkeleton, AgentGridSkeleton } from '../components/LoadingSkeletons';
import {
  Shield, LayoutDashboard, Crosshair, Network, List,
  RefreshCw, Download, Sun, Moon, Keyboard, Menu, X, Settings
} from 'lucide-react';
import { useMeshStore } from '../store/useMeshStore';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/dashboard';

interface DashboardProps {
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
  onShowShortcuts: () => void;
}

const NAV_ITEMS = [
  { id: 'overview',   icon: LayoutDashboard, label: 'Overview',         shortcut: '1' },
  { id: 'trust',      icon: Network,          label: 'Trust Graph',      shortcut: '2' },
  { id: 'threats',    icon: List,             label: 'Threat Feed',      shortcut: '3' },
  { id: 'simulator',  icon: Crosshair,        label: 'Attack Simulator', shortcut: '4' },
  { id: 'recovery',   icon: RefreshCw,        label: 'Self-Healing',     shortcut: '5' },
];

export const Dashboard: React.FC<DashboardProps> = ({
  theme,
  onToggleTheme,
  onShowShortcuts,
}) => {
  const { events, connected, metrics } = useSecurityEvents(WS_URL);
  const { setSettingsOpen } = useMeshStore();

  const [activeTab, setActiveTab] = useState('overview');
  const [agents, setAgents] = useState<any[]>([]);
  const [graphData, setGraphData] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [sidebarOpen, setSidebarOpen] = useState(false); // mobile sidebar

  // Events are already deduplicated inside useWebSocket (module-level buffer).
  // We use them directly — no client-side filter needed here.
  const dedupedEvents = events;

  // Periodic data fetch
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [agentsRes, graphRes] = await Promise.all([
          fetch(`${API_BASE}/agents`),
          fetch(`${API_BASE}/agents/trust-graph/viz`),
        ]);
        if (agentsRes.ok) setAgents(await agentsRes.json());
        if (graphRes.ok) setGraphData(await graphRes.json());
      } catch { /* backend offline during demo — fail silently */ }
    };
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  // Export event log
  const handleExport = useCallback(() => {
    const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agentops-events-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [events]);

  // Store handleExport in a ref so the keyboard handler never goes stale
  const handleExportRef = useRef(handleExport);
  useEffect(() => { handleExportRef.current = handleExport; }, [handleExport]);

  // Keyboard navigation shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      const item = NAV_ITEMS.find(n => n.shortcut === e.key);
      if (item) setActiveTab(item.id);
      if (e.key === 'e' || e.key === 'E') handleExportRef.current();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []); // stable — handleExport accessed via ref

  const handleLaunchAttack = async (scenario: string) => {
    try {
      await fetch(`${API_BASE}/simulator/attack/${scenario}`, { method: 'POST' });
    } catch { /* backend offline */ }
  };
  const handleRunDemo = async () => {
    try {
      await fetch(`${API_BASE}/simulator/demo`, { method: 'POST' });
    } catch { /* backend offline */ }
  };

  const avgTrust = agents.length > 0
    ? agents.reduce((acc: number, a: any) => acc + (a.trust_score ?? 1), 0) / agents.length
    : 1.0;

  const isDark = theme === 'dark';
  const bg = isDark ? 'bg-gray-950' : 'bg-gray-50';
  const sidebar = isDark ? 'bg-gray-900 border-gray-800' : 'bg-white border-gray-200';

  return (
    <div className={`flex h-screen ${bg} overflow-hidden`}>
      <SettingsModal />

      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed lg:relative inset-y-0 left-0 z-50 flex flex-col
          w-64 border-r ${sidebar} transition-transform duration-300
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        `}
      >
        {/* Logo */}
        <div className={`h-16 flex items-center px-4 border-b ${isDark ? 'border-gray-800' : 'border-gray-200'}`}>
          <Shield className="text-blue-500 shrink-0" size={24} />
          <span className={`ml-3 font-bold truncate ${isDark ? 'text-gray-100' : 'text-gray-900'}`}>
            AgentOps SOC
          </span>
          <button className="ml-auto lg:hidden" onClick={() => setSidebarOpen(false)}>
            <X size={18} className="text-gray-400" />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-4 space-y-1 px-2 overflow-y-auto">
          {NAV_ITEMS.map(item => (
            <button
              key={item.id}
              onClick={() => { setActiveTab(item.id); setSidebarOpen(false); }}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg transition-colors text-sm ${
                activeTab === item.id
                  ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                  : isDark
                    ? 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                    : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
              }`}
            >
              <div className="flex items-center">
                <item.icon size={18} />
                <span className="ml-3 font-medium">{item.label}</span>
              </div>
              <kbd className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                isDark ? 'bg-gray-800 text-gray-500 border border-gray-700' : 'bg-gray-100 text-gray-400 border border-gray-300'
              }`}>
                {item.shortcut}
              </kbd>
            </button>
          ))}
        </nav>

        {/* Footer actions */}
        <div className={`p-3 border-t ${isDark ? 'border-gray-800' : 'border-gray-200'} space-y-2`}>
          <button
            onClick={() => setSettingsOpen(true)}
            className={`w-full flex items-center px-3 py-2 rounded-lg text-sm transition-colors ${
              isDark ? 'text-gray-400 hover:bg-gray-800 hover:text-gray-200' : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            <Settings size={16} />
            <span className="ml-2">LLM Settings</span>
          </button>
          <button
            onClick={handleExport}
            className={`w-full flex items-center px-3 py-2 rounded-lg text-sm transition-colors ${
              isDark ? 'text-gray-400 hover:bg-gray-800 hover:text-gray-200' : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            <Download size={16} />
            <span className="ml-2">Export Event Log</span>
          </button>
          <button
            onClick={onToggleTheme}
            className={`w-full flex items-center px-3 py-2 rounded-lg text-sm transition-colors ${
              isDark ? 'text-gray-400 hover:bg-gray-800 hover:text-gray-200' : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            {isDark ? <Sun size={16} /> : <Moon size={16} />}
            <span className="ml-2">{isDark ? 'Light Mode' : 'Dark Mode'}</span>
            <kbd className={`ml-auto text-[10px] px-1.5 py-0.5 rounded font-mono ${
              isDark ? 'bg-gray-800 text-gray-500 border border-gray-700' : 'bg-gray-100 text-gray-400 border border-gray-300'
            }`}>T</kbd>
          </button>
          <button
            onClick={onShowShortcuts}
            className={`w-full flex items-center px-3 py-2 rounded-lg text-sm transition-colors ${
              isDark ? 'text-gray-400 hover:bg-gray-800 hover:text-gray-200' : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            <Keyboard size={16} />
            <span className="ml-2">Shortcuts</span>
            <kbd className={`ml-auto text-[10px] px-1.5 py-0.5 rounded font-mono ${
              isDark ? 'bg-gray-800 text-gray-500 border border-gray-700' : 'bg-gray-100 text-gray-400 border border-gray-300'
            }`}>?</kbd>
          </button>
        </div>

        {/* WS status */}
        <div className={`px-4 py-3 border-t ${isDark ? 'border-gray-800' : 'border-gray-200'} flex items-center`}>
          <div className="relative flex h-2.5 w-2.5 mr-2 shrink-0">
            {connected && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />}
            <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
          </div>
          <span className={`text-xs font-mono ${isDark ? 'text-gray-500' : 'text-gray-400'}`}>
            {connected ? 'LIVE' : 'OFFLINE'}
          </span>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">

        {/* Mobile top bar */}
        <div className={`flex lg:hidden items-center h-14 px-4 border-b ${isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-white'}`}>
          <button onClick={() => setSidebarOpen(true)} className="mr-3">
            <Menu size={20} className={isDark ? 'text-gray-400' : 'text-gray-600'} />
          </button>
          <Shield size={20} className="text-blue-500" />
          <span className={`ml-2 font-bold text-sm ${isDark ? 'text-gray-100' : 'text-gray-900'}`}>AgentOps SOC</span>
          <div className="ml-auto flex items-center space-x-2">
            <div className={`relative flex h-2 w-2`}>
              {connected && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />}
              <span className={`relative inline-flex rounded-full h-2 w-2 ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
            </div>
          </div>
        </div>

        {/* CRITICAL threat overlay */}
        {events[0]?.severity === 'CRITICAL' && (
          <div className="absolute inset-0 bg-red-900/5 pointer-events-none z-30 animate-pulse" />
        )}

        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          {/* Metrics bar */}
          {!connected && events.length === 0 ? (
            <MetricsBarSkeleton />
          ) : (
            <MetricsBar
              connected={connected}
              metrics={metrics}
              agentCount={agents.length}
              avgTrust={avgTrust}
            />
          )}

          {/* Tab content */}
          <div className="h-[calc(100vh-200px)] min-h-[400px]">
            {activeTab === 'overview' && (
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 h-full">
                <div className="xl:col-span-2 flex flex-col gap-4 min-h-0">
                  <div className="flex-1 min-h-0">
                    <TrustGraphViz nodes={graphData.nodes} links={graphData.edges} />
                  </div>
                  <div className="flex-1 min-h-0">
                    {agents.length === 0 && !connected ? <AgentGridSkeleton /> : <AgentGrid agents={agents} />}
                  </div>
                </div>
                <div className="xl:col-span-1 min-h-0">
                  {!connected && events.length === 0 ? <ThreatFeedSkeleton /> : <ThreatFeed events={dedupedEvents} />}
                </div>
              </div>
            )}

            {activeTab === 'trust' && (
              <TrustGraphViz nodes={graphData.nodes} links={graphData.edges} />
            )}

            {activeTab === 'threats' && (
              <div className="max-w-4xl mx-auto h-full">
                {!connected && events.length === 0 ? <ThreatFeedSkeleton /> : <ThreatFeed events={dedupedEvents} />}
              </div>
            )}

            {activeTab === 'simulator' && (
              <AttackSimulator
                onLaunchAttack={handleLaunchAttack}
                onRunDemo={handleRunDemo}
                recentEvents={dedupedEvents}
              />
            )}

            {activeTab === 'recovery' && (
              <SelfHealingEngine recentEvents={dedupedEvents} theme={theme} />
            )}
          </div>
        </main>
      </div>
    </div>
  );
};
