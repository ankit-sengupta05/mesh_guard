import React, { useState } from 'react';
import { SecurityEvent } from '../hooks/useWebSocket';
import { ShieldAlert, Info, AlertTriangle, AlertCircle, ChevronDown, ChevronUp } from 'lucide-react';

interface ThreatFeedProps {
  events: SecurityEvent[];
}

export const ThreatFeed: React.FC<ThreatFeedProps> = ({ events }) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filteredEvents = events.filter(e => 
    filterSeverity === 'ALL' || e.severity === filterSeverity
  );

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-red-500/10 text-red-500 border-red-500/20';
      case 'HIGH': return 'bg-orange-500/10 text-orange-500 border-orange-500/20';
      case 'MEDIUM': return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
      default: return 'bg-green-500/10 text-green-500 border-green-500/20';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return <ShieldAlert size={16} />;
      case 'HIGH': return <AlertTriangle size={16} />;
      case 'MEDIUM': return <AlertCircle size={16} />;
      default: return <Info size={16} />;
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden flex flex-col h-full max-h-[600px]">
      <div className="p-4 border-b border-gray-800 flex justify-between items-center bg-gray-950/50">
        <h2 className="text-lg font-semibold text-gray-200">Live Threat Feed</h2>
        
        <div className="flex space-x-2">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-3 py-1 text-xs font-medium rounded-full transition-colors ${
                filterSeverity === sev 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-y-auto flex-1 p-2 space-y-2">
        {filteredEvents.length === 0 ? (
          <div className="h-full flex items-center justify-center text-gray-500">
            No events match current filter.
          </div>
        ) : (
          filteredEvents.map(event => {
            const isExpanded = expandedId === event.event_id;
            const timeStr = new Date(event.timestamp).toLocaleTimeString();
            
            return (
              <div 
                key={event.event_id} 
                className={`border rounded flex flex-col transition-all ${getSeverityColor(event.severity)}`}
              >
                <div 
                  className="p-3 flex items-center cursor-pointer select-none"
                  onClick={() => setExpandedId(isExpanded ? null : event.event_id)}
                >
                  <div className="w-24 text-xs font-mono opacity-70 shrink-0">
                    {timeStr}
                  </div>
                  
                  <div className="flex items-center w-28 shrink-0 font-medium text-xs tracking-wider">
                    <span className="mr-2">{getSeverityIcon(event.severity)}</span>
                    {event.severity}
                  </div>
                  
                  <div className="w-48 text-sm font-semibold truncate shrink-0 px-2 opacity-90">
                    {event.event_type}
                  </div>
                  
                  <div className="flex-1 text-sm truncate opacity-80 font-mono text-xs">
                    {event.agent_id}
                  </div>
                  
                  <div className="shrink-0 opacity-50 ml-2">
                    {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </div>
                </div>

                {isExpanded && (
                  <div className="p-3 border-t border-current/10 bg-black/20 text-xs font-mono overflow-x-auto">
                    <pre className="text-gray-300 whitespace-pre-wrap">
                      {JSON.stringify(event.details, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
