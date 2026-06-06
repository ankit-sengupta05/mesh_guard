import React from 'react';
import { Activity, ShieldAlert, ShieldCheck, Users, Zap } from 'lucide-react';

interface MetricsBarProps {
  connected: boolean;
  metrics: {
    total: number;
    critical: number;
    high: number;
    recoveries: number;
  };
  agentCount: number;
  avgTrust: number;
}

export const MetricsBar: React.FC<MetricsBarProps> = ({
  connected,
  metrics,
  agentCount,
  avgTrust
}) => {
  const blockRate = metrics.total > 0
    ? Math.round(((metrics.critical + metrics.high) / metrics.total) * 100)
    : 0;

  return (
    <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">

      {/* Total Threats */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col justify-between">
        <div className="flex justify-between items-center text-gray-400 mb-2">
          <span className="text-sm font-medium uppercase tracking-wider">Total Threats</span>
          <ShieldAlert size={18} className="text-red-500" />
        </div>
        <div className="text-3xl font-bold text-gray-100">{metrics.total}</div>
        <div className="text-xs text-gray-500 mt-2">
          {metrics.critical} CRITICAL, {metrics.high} HIGH
        </div>
      </div>

      {/* Threats Blocked */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col justify-between">
        <div className="flex justify-between items-center text-gray-400 mb-2">
          <span className="text-sm font-medium uppercase tracking-wider">Blocked</span>
          <ShieldCheck size={18} className="text-green-500" />
        </div>
        <div className="text-3xl font-bold text-gray-100">{metrics.critical + metrics.high}</div>
        <div className="text-xs text-green-500 mt-2 font-mono">
          {blockRate}% Block Rate
        </div>
      </div>

      {/* Active Agents */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col justify-between">
        <div className="flex justify-between items-center text-gray-400 mb-2">
          <span className="text-sm font-medium uppercase tracking-wider">Active Agents</span>
          <Users size={18} className="text-blue-500" />
        </div>
        <div className="text-3xl font-bold text-gray-100">{agentCount}</div>
        <div className="flex items-center text-xs text-gray-500 mt-2">
          <span className="w-2 h-2 rounded-full bg-green-500 mr-2"></span>
          Online
        </div>
      </div>

      {/* Avg Trust Score */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col justify-between">
        <div className="flex justify-between items-center text-gray-400 mb-2">
          <span className="text-sm font-medium uppercase tracking-wider">Avg Trust Score</span>
          <Activity size={18} className={avgTrust > 0.8 ? 'text-green-500' : 'text-yellow-500'} />
        </div>
        <div className="text-3xl font-bold text-gray-100">{avgTrust.toFixed(2)}</div>
        <div className="w-full bg-gray-800 h-1.5 mt-3 rounded-full overflow-hidden">
          <div
            className={`h-full ${avgTrust > 0.8 ? 'bg-green-500' : 'bg-yellow-500'}`}
            style={{ width: `${avgTrust * 100}%` }}
          />
        </div>
      </div>

      {/* Recoveries */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col justify-between relative overflow-hidden">
        <div className="flex justify-between items-center text-gray-400 mb-2 z-10">
          <span className="text-sm font-medium uppercase tracking-wider">Recoveries</span>
          <Zap size={18} className="text-purple-500" />
        </div>
        <div className="text-3xl font-bold text-gray-100 z-10">{metrics.recoveries}</div>
        <div className="text-xs text-gray-500 mt-2 z-10">
          Self-healed today
        </div>

        {/* Subtle background pulse if there's a recent recovery */}
        {metrics.recoveries > 0 && (
          <div className="absolute inset-0 bg-purple-900/10 animate-pulse z-0"></div>
        )}
      </div>

    </div>
  );
};
