import React from 'react';
import { SecurityEvent } from '../hooks/useWebSocket';
import { ShieldAlert, ArrowRight, CheckCircle2, RotateCw } from 'lucide-react';

interface RecoveryTimelineProps {
  recentEvents: SecurityEvent[];
}

export const RecoveryTimeline: React.FC<RecoveryTimelineProps> = ({ recentEvents }) => {
  // Filter for recovery events and group them conceptually
  const recoveryEvents = recentEvents.filter(e =>
    e.event_type === 'RECOVERY_STARTED' || e.event_type === 'RECOVERY_COMPLETE'
  );

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 h-full overflow-hidden flex flex-col">
      <div className="flex justify-between items-center mb-4 border-b border-gray-800 pb-2">
        <h2 className="text-lg font-semibold text-gray-200 flex items-center">
          <RotateCw size={18} className="mr-2 text-purple-500" />
          Self-Healing Engine
        </h2>
        <span className="text-xs text-gray-500 font-mono bg-gray-800 px-2 py-1 rounded">8-Step Protocol</span>
      </div>

      <div className="overflow-y-auto flex-1 pr-2">
        {recoveryEvents.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-gray-600 space-y-3">
            <ShieldAlert size={32} className="opacity-20" />
            <p className="text-sm">No recent recovery cycles.</p>
            <p className="text-xs text-center max-w-xs">The self-healing engine automatically snapshots, isolates, and replaces compromised agents.</p>
          </div>
        ) : (
          <div className="space-y-6">
            {recoveryEvents.map((event, index) => {
              const details = event.details || {};
              const steps = details.steps || ['PAUSE', 'SNAPSHOT', 'ANALYZE', 'SPAWN', 'RESTORE', 'REPLAY', 'VERIFY', 'REPORT'];
              const isSuccess = details.success !== false;

              return (
                <div key={event.event_id} className="border border-gray-800 rounded-lg bg-gray-950 p-3 relative overflow-hidden">
                  {/* Background success/fail glow */}
                  <div className={`absolute top-0 left-0 w-1 h-full ${isSuccess ? 'bg-green-500' : 'bg-red-500'}`}></div>

                  <div className="flex justify-between items-center mb-3 ml-2">
                    <div className="text-xs text-gray-400 font-mono">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </div>
                    <div className={`text-[10px] uppercase px-2 py-0.5 rounded font-bold tracking-wider ${
                      isSuccess ? 'bg-green-900/30 text-green-500' : 'bg-red-900/30 text-red-500'
                    }`}>
                      {isSuccess ? 'RECOVERED' : 'FAILED'}
                    </div>
                  </div>

                  <div className="flex items-center justify-center space-x-3 mb-4 ml-2">
                    <div className="text-center">
                      <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Compromised</div>
                      <div className="text-xs font-mono bg-red-900/20 text-red-400 border border-red-900/50 px-2 py-1 rounded truncate w-24">
                        {details.original_agent_id?.substring(0,8) || 'unknown'}
                      </div>
                    </div>

                    <ArrowRight size={16} className="text-gray-600" />

                    <div className="text-center">
                      <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Replacement</div>
                      <div className="text-xs font-mono bg-green-900/20 text-green-400 border border-green-900/50 px-2 py-1 rounded truncate w-24">
                        {event.agent_id?.substring(0,8) || 'unknown'}
                      </div>
                    </div>
                  </div>

                  <div className="ml-2 grid grid-cols-4 gap-2">
                    {['PAUSE', 'SNAPSHOT', 'ANALYZE', 'SPAWN', 'RESTORE', 'REPLAY', 'VERIFY', 'REPORT'].map((stepName, i) => {
                      const completed = steps.includes(stepName) || steps.includes(`${stepName}_DELEGATED`);
                      return (
                        <div key={stepName} className="flex flex-col items-center">
                          <div className={`w-full h-1 rounded mb-1 ${
                            completed ? 'bg-green-500' : 'bg-gray-800'
                          }`}></div>
                          <span className={`text-[9px] font-mono tracking-tighter ${
                            completed ? 'text-gray-300' : 'text-gray-600'
                          }`}>
                            {stepName}
                          </span>
                        </div>
                      );
                    })}
                  </div>

                  {details.duration_ms && (
                    <div className="mt-3 ml-2 text-right text-[10px] text-gray-500 font-mono">
                      Cycle completed in {details.duration_ms}ms
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
