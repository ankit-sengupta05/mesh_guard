import React, { useMemo } from 'react';
import { Server, Shield, Activity, HardDrive } from 'lucide-react';

interface AgentData {
  id?: string;
  agent_id?: string;
  name: string;
  role: string;
  trust_score: number;
  status: 'ACTIVE' | 'SUSPENDED' | 'RECOVERING' | 'active' | 'suspended' | 'recovering';
}

interface AgentGridProps {
  agents: AgentData[];
  onSelectAgent?: (id: string) => void;
}

/** Stable pseudo-random number seeded by a string — avoids flickering on re-renders. */
function seededRandom(seed: string): number {
  let h = 0;
  for (let i = 0; i < seed.length; i++) {
    h = (Math.imul(31, h) + seed.charCodeAt(i)) | 0;
  }
  return (Math.abs(h) % 1000) / 1000;
}

export const AgentGrid: React.FC<AgentGridProps> = ({ agents, onSelectAgent }) => {
  // Compute stable memory mock values once per agent list change — NOT on every render
  const memoryValues = useMemo(() => {
    return agents.map(agent => {
      const id = agent.agent_id ?? agent.id ?? agent.name;
      const memMB = (seededRandom(id + 'mb') * 40 + 10).toFixed(1);
      const memPct = seededRandom(id + 'pct') * 60 + 20;
      return { memMB, memPct };
    });
  }, [agents]);

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 h-full">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-semibold text-gray-200">Active Swarm</h2>
        <span className="text-xs text-gray-500 font-mono">{agents.length} nodes online</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-3 overflow-y-auto max-h-[500px] pr-2">
        {agents.map((agent, idx) => {
          const agentId = agent.agent_id ?? agent.id ?? '';
          // Normalise status to uppercase for consistent comparison
          const statusUpper = (agent.status ?? 'ACTIVE').toUpperCase() as
            | 'ACTIVE'
            | 'SUSPENDED'
            | 'RECOVERING';
          const { memMB, memPct } = memoryValues[idx] ?? { memMB: '20.0', memPct: 40 };

          return (
            <div
              key={agentId || agent.name}
              onClick={() => onSelectAgent?.(agentId)}
              className={`border rounded-lg p-3 cursor-pointer transition-all hover:bg-gray-800 ${
                statusUpper === 'RECOVERING'
                  ? 'border-red-500/50 bg-red-950/20 animate-pulse'
                  : statusUpper === 'SUSPENDED'
                  ? 'border-gray-700 bg-gray-900/50 opacity-50'
                  : 'border-gray-800 bg-gray-900/80'
              }`}
            >
              <div className="flex justify-between items-start mb-2">
                <div className="flex items-center space-x-2">
                  <Server size={16} className="text-blue-400" />
                  <span className="text-sm font-semibold text-gray-200">{agent.name}</span>
                </div>

                <div className="flex items-center">
                  <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-blue-900/30 text-blue-400 mr-2 border border-blue-800">
                    {agent.role}
                  </span>

                  {/* Status Dot */}
                  <span className="relative flex h-2.5 w-2.5">
                    {statusUpper === 'ACTIVE' && (
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                    )}
                    <span
                      className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                        statusUpper === 'ACTIVE'
                          ? 'bg-green-500'
                          : statusUpper === 'RECOVERING'
                          ? 'bg-red-500'
                          : 'bg-gray-500'
                      }`}
                    ></span>
                  </span>
                </div>
              </div>

              <div className="mt-4 space-y-3">
                {/* Trust Score */}
                <div>
                  <div className="flex justify-between text-xs mb-1 text-gray-400 font-mono">
                    <span className="flex items-center">
                      <Shield size={12} className="mr-1" /> Trust
                    </span>
                    <span>{(agent.trust_score ?? 0).toFixed(2)}</span>
                  </div>
                  <div className="w-full bg-gray-800 rounded-full h-1">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        agent.trust_score > 0.8
                          ? 'bg-green-500'
                          : agent.trust_score > 0.4
                          ? 'bg-yellow-500'
                          : 'bg-red-500'
                      }`}
                      style={{ width: `${Math.max(0, Math.min(100, (agent.trust_score ?? 0) * 100))}%` }}
                    ></div>
                  </div>
                </div>

                {/* Memory Usage (stable mock visual) */}
                <div>
                  <div className="flex justify-between text-xs mb-1 text-gray-400 font-mono">
                    <span className="flex items-center">
                      <HardDrive size={12} className="mr-1" /> Memory
                    </span>
                    <span>{memMB} MB</span>
                  </div>
                  <div className="w-full bg-gray-800 rounded-full h-1">
                    <div
                      className="bg-blue-500 h-full rounded-full"
                      style={{ width: `${memPct}%` }}
                    ></div>
                  </div>
                </div>
              </div>

              <div className="mt-3 pt-3 border-t border-gray-800 text-[10px] text-gray-500 font-mono flex justify-between">
                <span>ID: {agentId.substring(0, 8)}...</span>
                <span className="flex items-center">
                  <Activity size={10} className="mr-1 text-green-500" />
                  {statusUpper === 'ACTIVE' ? 'Active' : statusUpper === 'RECOVERING' ? 'Recovering' : 'Suspended'}
                </span>
              </div>
            </div>
          );
        })}

        {agents.length === 0 && (
          <div className="col-span-full h-40 flex items-center justify-center text-gray-500 font-mono text-sm">
            No agents found. Swarm inactive.
          </div>
        )}
      </div>
    </div>
  );
};
