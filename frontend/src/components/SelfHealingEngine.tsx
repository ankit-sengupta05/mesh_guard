import React, { useEffect, useState, useCallback } from 'react';
import {
  RotateCw, ShieldCheck, ArrowRight,
  Activity, Cpu, CheckCircle2, XCircle
} from 'lucide-react';
import { SecurityEvent } from '../hooks/useWebSocket';

interface AgentHealth {
  name: string;
  role: string;
  trust_score: number;
  is_anomalous: boolean;
  anomaly_score: number;
  action: string;
  deviants: string[];
}

interface RecoveryRecord {
  recovery_id: string;
  agent_id: string;
  original_id: string;
  reason: string;
  success: boolean;
  duration_ms: number;
  steps: string[];
  timestamp: string;
}

interface HealingStatus {
  agent_health: Record<string, AgentHealth>;
  tick: number;
  recent_recoveries: RecoveryRecord[];
}

interface SelfHealingEngineProps {
  recentEvents: SecurityEvent[];
  theme: 'dark' | 'light';
}

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

const STEPS = ['PAUSE', 'SNAPSHOT', 'ANALYZE', 'SPAWN', 'RESTORE', 'REPLAY', 'VERIFY', 'REPORT'];

function actionColor(action: string) {
  switch (action) {
    case 'ALLOW': return 'text-green-400';
    case 'WARN':  return 'text-yellow-400';
    case 'PAUSE': return 'text-orange-400';
    case 'SUSPEND': return 'text-red-400';
    case 'TERMINATE': return 'text-red-600';
    default: return 'text-gray-400';
  }
}

function actionBg(action: string) {
  switch (action) {
    case 'ALLOW': return 'bg-green-900/20 border-green-800/40';
    case 'WARN':  return 'bg-yellow-900/20 border-yellow-800/40';
    case 'PAUSE': return 'bg-orange-900/20 border-orange-800/40';
    case 'SUSPEND': return 'bg-red-900/20 border-red-800/40';
    default: return 'bg-gray-800/20 border-gray-700/40';
  }
}

export const SelfHealingEngine: React.FC<SelfHealingEngineProps> = ({ recentEvents, theme }) => {
  const [status, setStatus]     = useState<HealingStatus | null>(null);
  const [loading, setLoading]   = useState(true);
  const [lastFetch, setLastFetch] = useState<Date | null>(null);
  const [triggering, setTriggering] = useState<string | null>(null);

  const isDark = theme === 'dark';

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/healing/status`);
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
        setLastFetch(new Date());
      }
    } catch {
      // backend offline — keep showing stale data
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 8000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  const triggerRecovery = async (agentId: string) => {
    setTriggering(agentId);
    try {
      await fetch(`${API_BASE}/healing/trigger/${agentId}?reason=Manual+trigger+via+dashboard`, {
        method: 'POST',
      });
      // Refresh after a short delay
      setTimeout(fetchStatus, 1500);
    } finally {
      setTimeout(() => setTriggering(null), 2000);
    }
  };

  const agents     = status ? Object.entries(status.agent_health) : [];
  const recoveries = status?.recent_recoveries ?? [];
  const anomalous  = agents.filter(([, h]) => h.is_anomalous);
  const tick       = status?.tick ?? 0;

  // Also surface recovery events from WebSocket
  const wsRecoveries = recentEvents.filter(
    e => e.event_type === 'RECOVERY_STARTED' || e.event_type === 'RECOVERY_COMPLETE'
  );

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 h-full">

      {/* ── Left panel: agent health grid ─────────────────────────────── */}
      <div className={`rounded-lg border flex flex-col overflow-hidden ${isDark ? 'bg-gray-900 border-gray-800' : 'bg-white border-gray-200'}`}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 shrink-0">
          <div className="flex items-center gap-2">
            <Activity size={16} className="text-purple-400" />
            <h2 className={`text-sm font-semibold ${isDark ? 'text-gray-200' : 'text-gray-800'}`}>
              Agent Health Monitor
            </h2>
          </div>
          <div className="flex items-center gap-2">
            {tick > 0 && (
              <span className="text-[10px] font-mono text-gray-500">tick #{tick}</span>
            )}
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${anomalous.length > 0 ? 'bg-red-900/30 text-red-400' : 'bg-green-900/20 text-green-500'}`}>
              {anomalous.length > 0 ? `${anomalous.length} anomal${anomalous.length === 1 ? 'y' : 'ies'}` : 'All Clear'}
            </span>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-3 space-y-2">
          {loading && agents.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-gray-600 gap-2">
              <RotateCw size={24} className="animate-spin opacity-40" />
              <p className="text-sm">Polling agent health…</p>
            </div>
          ) : agents.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-gray-600 gap-3">
              <Cpu size={32} className="opacity-20" />
              <p className="text-sm">No agents being monitored yet.</p>
              <p className="text-xs opacity-60 text-center">Agents appear after startup registration completes.</p>
            </div>
          ) : (
            agents.map(([agentId, health]) => (
              <div
                key={agentId}
                className={`rounded-lg border p-3 ${actionBg(health.action)} relative overflow-hidden`}
              >
                {/* Left accent bar */}
                <div className={`absolute left-0 top-0 bottom-0 w-0.5 ${
                  health.action === 'ALLOW' ? 'bg-green-500' :
                  health.action === 'WARN' ? 'bg-yellow-500' :
                  'bg-red-500'
                }`} />

                <div className="flex items-start justify-between ml-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-semibold text-gray-200 truncate">{health.name}</span>
                      <span className="text-[10px] font-mono text-gray-500 uppercase">{health.role}</span>
                    </div>

                    {/* Trust score bar */}
                    <div className="flex items-center gap-2 mb-1.5">
                      <div className="flex-1 bg-gray-800 rounded-full h-1">
                        <div
                          className="h-1 rounded-full transition-all duration-500"
                          style={{
                            width: `${Math.round((health.trust_score ?? 1) * 100)}%`,
                            backgroundColor: health.trust_score > 0.8 ? '#22c55e' : health.trust_score > 0.4 ? '#eab308' : '#ef4444',
                          }}
                        />
                      </div>
                      <span className="text-[10px] font-mono text-gray-400 w-8 text-right">
                        {Math.round((health.trust_score ?? 1) * 100)}%
                      </span>
                    </div>

                    {/* Anomaly score bar */}
                    {health.anomaly_score > 0 && (
                      <div className="flex items-center gap-2 mb-1.5">
                        <div className="flex-1 bg-gray-800 rounded-full h-1">
                          <div
                            className="h-1 rounded-full bg-orange-500 transition-all duration-500"
                            style={{ width: `${Math.round(health.anomaly_score * 100)}%` }}
                          />
                        </div>
                        <span className="text-[10px] font-mono text-orange-400 w-8 text-right">
                          {Math.round(health.anomaly_score * 100)}%
                        </span>
                      </div>
                    )}

                    {health.deviants.length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {health.deviants.map((d, i) => (
                          <span key={i} className="text-[9px] font-mono bg-red-900/30 text-red-400 px-1.5 py-0.5 rounded">
                            {d}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="flex flex-col items-end gap-1 ml-2 shrink-0">
                    <span className={`text-[10px] font-bold uppercase ${actionColor(health.action)}`}>
                      {health.action}
                    </span>
                    {health.is_anomalous && (
                      <button
                        onClick={() => triggerRecovery(agentId)}
                        disabled={triggering === agentId}
                        className="text-[9px] bg-purple-900/40 hover:bg-purple-800/60 text-purple-300 border border-purple-700/40 rounded px-1.5 py-0.5 font-mono transition-colors disabled:opacity-50"
                      >
                        {triggering === agentId ? 'Healing…' : 'Heal →'}
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {lastFetch && (
          <div className="px-4 py-2 border-t border-gray-800 text-[10px] text-gray-600 font-mono">
            Last updated: {lastFetch.toLocaleTimeString()} · auto-refresh every 8s
          </div>
        )}
      </div>

      {/* ── Right panel: recovery timeline ────────────────────────────── */}
      <div className={`rounded-lg border flex flex-col overflow-hidden ${isDark ? 'bg-gray-900 border-gray-800' : 'bg-white border-gray-200'}`}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 shrink-0">
          <div className="flex items-center gap-2">
            <RotateCw size={16} className="text-purple-400" />
            <h2 className={`text-sm font-semibold ${isDark ? 'text-gray-200' : 'text-gray-800'}`}>
              Recovery Cycles
            </h2>
          </div>
          <span className="text-xs text-gray-500 font-mono bg-gray-800 px-2 py-0.5 rounded">8-Step Protocol</span>
        </div>

        <div className="flex-1 overflow-y-auto p-3 space-y-3">
          {recoveries.length === 0 && wsRecoveries.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-gray-600 gap-3">
              <ShieldCheck size={36} className="opacity-20" />
              <p className="text-sm font-semibold">No recovery cycles yet</p>
              <p className="text-xs opacity-60 text-center max-w-xs">
                The self-healing engine monitors all agents continuously.
                Recovery cycles appear here when anomalies trigger the 8-step protocol.
              </p>
              <div className="mt-2 p-3 rounded-lg border border-gray-800 bg-gray-800/30 w-full max-w-xs">
                <div className="text-[10px] font-bold text-gray-400 mb-2 uppercase tracking-wider">Protocol steps</div>
                <div className="grid grid-cols-4 gap-1">
                  {STEPS.map(s => (
                    <div key={s} className="text-center">
                      <div className="w-full h-0.5 rounded bg-gray-700 mb-1" />
                      <span className="text-[8px] font-mono text-gray-600">{s}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <>
              {recoveries.map(r => (
                <RecoveryCard key={r.recovery_id} record={r} />
              ))}
              {/* Supplement with WS events not in the API history */}
              {wsRecoveries
                .filter(e => !recoveries.some(r => r.recovery_id === e.details?.recovery_id))
                .map(e => (
                  <WsRecoveryCard key={e.event_id} event={e} />
                ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

// ── Sub-components ─────────────────────────────────────────────────────────

const RecoveryCard: React.FC<{ record: RecoveryRecord }> = ({ record }) => {
  const completed = (step: string) =>
    record.steps.some(s => s === step || s === `${step}_DELEGATED`);

  return (
    <div className="border border-gray-800 rounded-lg bg-gray-950 p-3 relative overflow-hidden">
      <div className={`absolute left-0 top-0 bottom-0 w-1 ${record.success ? 'bg-green-500' : 'bg-red-500'}`} />

      <div className="flex justify-between items-center mb-2 ml-2">
        <div className="flex items-center gap-2">
          {record.success
            ? <CheckCircle2 size={14} className="text-green-500" />
            : <XCircle size={14} className="text-red-500" />}
          <span className="text-xs font-mono text-gray-400">{new Date(record.timestamp).toLocaleTimeString()}</span>
        </div>
        <span className={`text-[10px] uppercase px-2 py-0.5 rounded font-bold tracking-wider ${
          record.success ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'
        }`}>
          {record.success ? 'RECOVERED' : 'FAILED'}
        </span>
      </div>

      <div className="flex items-center gap-3 mb-3 ml-2">
        <div className="text-center">
          <div className="text-[9px] text-gray-500 uppercase mb-0.5">Compromised</div>
          <div className="text-[10px] font-mono bg-red-900/20 text-red-400 border border-red-900/40 px-2 py-0.5 rounded truncate w-20">
            {record.original_id.substring(0, 8)}…
          </div>
        </div>
        <ArrowRight size={14} className="text-gray-600 shrink-0" />
        <div className="text-center">
          <div className="text-[9px] text-gray-500 uppercase mb-0.5">Replacement</div>
          <div className="text-[10px] font-mono bg-green-900/20 text-green-400 border border-green-900/40 px-2 py-0.5 rounded truncate w-20">
            {record.agent_id.substring(0, 8)}…
          </div>
        </div>
      </div>

      <div className="ml-2 grid grid-cols-4 gap-1.5 mb-2">
        {STEPS.map(step => (
          <div key={step} className="flex flex-col items-center">
            <div className={`w-full h-1 rounded mb-0.5 ${completed(step) ? 'bg-green-500' : 'bg-gray-800'}`} />
            <span className={`text-[8px] font-mono ${completed(step) ? 'text-gray-400' : 'text-gray-700'}`}>
              {step}
            </span>
          </div>
        ))}
      </div>

      <div className="ml-2 flex justify-between text-[9px] text-gray-600 font-mono">
        <span className="truncate max-w-[60%]">{record.reason}</span>
        {record.duration_ms > 0 && <span>{record.duration_ms}ms</span>}
      </div>
    </div>
  );
};

const WsRecoveryCard: React.FC<{ event: SecurityEvent }> = ({ event }) => {
  const isComplete = event.event_type === 'RECOVERY_COMPLETE';
  const d = event.details || {};
  return (
    <div className="border border-gray-800 rounded-lg bg-gray-950 p-3 relative overflow-hidden opacity-80">
      <div className={`absolute left-0 top-0 bottom-0 w-1 ${isComplete && d.success !== false ? 'bg-green-500' : 'bg-yellow-500'}`} />
      <div className="flex justify-between items-center mb-2 ml-2">
        <span className="text-xs font-mono text-gray-400">{new Date(event.timestamp).toLocaleTimeString()}</span>
        <span className="text-[10px] font-mono text-purple-400 uppercase">{event.event_type}</span>
      </div>
      {d.original_agent_id && (
        <div className="flex items-center gap-3 ml-2 mb-2">
          <div className="text-[10px] font-mono bg-red-900/20 text-red-400 border border-red-900/40 px-2 py-0.5 rounded">
            {String(d.original_agent_id).substring(0, 8)}…
          </div>
          <ArrowRight size={12} className="text-gray-600" />
          <div className="text-[10px] font-mono bg-green-900/20 text-green-400 border border-green-900/40 px-2 py-0.5 rounded">
            {event.agent_id?.substring(0, 8) ?? 'unknown'}…
          </div>
        </div>
      )}
      {d.steps && Array.isArray(d.steps) && (
        <div className="ml-2 grid grid-cols-4 gap-1">
          {STEPS.map(step => {
            const done = (d.steps as string[]).some((s: string) => s === step || s === `${step}_DELEGATED`);
            return (
              <div key={step} className="flex flex-col items-center">
                <div className={`w-full h-0.5 rounded mb-0.5 ${done ? 'bg-green-500' : 'bg-gray-800'}`} />
                <span className={`text-[8px] font-mono ${done ? 'text-gray-400' : 'text-gray-700'}`}>{step}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
