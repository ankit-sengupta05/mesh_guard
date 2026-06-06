import React, { useState, useEffect } from 'react';
import { Play, Terminal, ShieldAlert, Crosshair, Loader } from 'lucide-react';
import { SecurityEvent } from '../hooks/useWebSocket';

interface Scenario {
  name: string;
  description: string;
  target: string;
  injection_point: string;
}

interface AttackSimulatorProps {
  onLaunchAttack: (scenario: string) => Promise<void>;
  onRunDemo: () => Promise<void>;
  recentEvents: SecurityEvent[];
}

// Hardcoded for UI rendering purposes to match backend
const MOCK_SCENARIOS: Scenario[] = [
  { name: "PROMPT_INJECTION_BASIC", description: "Classic override instruction injected into an agent's context.", target: "web_agent", injection_point: "tool_response" },
  { name: "HIDDEN_UNICODE_INJECTION", description: "Zero-width characters hiding malicious text.", target: "web_agent", injection_point: "webpage_content" },
  { name: "FAKE_TOOL_RESPONSE", description: "Malicious JSON structure spoofing a legitimate tool output.", target: "api_agent", injection_point: "api_response" },
  { name: "IDENTITY_SPOOFING", description: "An agent falsely claims to be the SENTINEL.", target: "trust_graph", injection_point: "agent_message" },
  { name: "API_POISONING", description: "A hijacked API returns nested instruction payload.", target: "api_agent", injection_point: "json_parse" },
  { name: "MEMORY_BOUNDARY_VIOLATION", description: "An executor attempts to read planner's private memory.", target: "memory_manager", injection_point: "memory_read" },
  { name: "TRUST_ESCALATION", description: "Flooding the trust graph with fake successful interactions.", target: "trust_graph", injection_point: "interaction_recording" },
  { name: "SYSTEM_PROMPT_EXFILTRATION", description: "Attempting to steal orchestrator's core instructions.", target: "planner_agent", injection_point: "user_input" }
];

export const AttackSimulator: React.FC<AttackSimulatorProps> = ({ 
  onLaunchAttack, 
  onRunDemo,
  recentEvents
}) => {
  const [activeAttack, setActiveAttack] = useState<string | null>(null);
  const [demoRunning, setDemoRunning] = useState(false);

  // Find the most recent SIMULATOR event
  const latestSimEvent = recentEvents.find(e => e.source === 'simulator');
  const simResult = latestSimEvent?.details;

  const handleLaunch = async (name: string) => {
    setActiveAttack(name);
    try {
      await onLaunchAttack(name);
    } finally {
      setTimeout(() => setActiveAttack(null), 1500); // Keep loading state briefly
    }
  };

  const handleDemo = async () => {
    setDemoRunning(true);
    try {
      await onRunDemo();
    } finally {
      setTimeout(() => setDemoRunning(false), 24000); // Demo takes ~24s (8 * 3s)
    }
  };

  return (
    <div className="flex flex-col lg:flex-row gap-6 h-full">
      {/* Left side: Scenarios */}
      <div className="lg:w-2/3 bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col h-full">
        <div className="flex justify-between items-center mb-4 border-b border-gray-800 pb-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-200 flex items-center">
              <Crosshair size={20} className="mr-2 text-red-500" />
              Live Attack Simulator
            </h2>
            <p className="text-sm text-gray-500 mt-1">Inject adversarial payloads directly into the live mesh.</p>
          </div>
          
          <button 
            onClick={handleDemo}
            disabled={demoRunning}
            className={`flex items-center px-4 py-2 rounded-md font-medium text-sm transition-colors ${
              demoRunning 
                ? 'bg-gray-800 text-gray-500 cursor-not-allowed' 
                : 'bg-red-600 hover:bg-red-700 text-white shadow-lg shadow-red-900/20'
            }`}
          >
            {demoRunning ? (
              <><Loader size={16} className="mr-2 animate-spin" /> Sequence Running...</>
            ) : (
              <><Play size={16} className="mr-2" /> Run Full Demo Sequence</>
            )}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 overflow-y-auto pr-2 flex-1">
          {MOCK_SCENARIOS.map(scenario => (
            <div key={scenario.name} className="border border-gray-800 bg-gray-950 rounded-lg p-3 flex flex-col">
              <div className="flex justify-between items-start mb-2">
                <h3 className="text-sm font-semibold text-gray-300 truncate pr-2" title={scenario.name}>
                  {scenario.name.replace(/_/g, ' ')}
                </h3>
                <span className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 font-mono shrink-0">
                  {scenario.target}
                </span>
              </div>
              
              <p className="text-xs text-gray-500 mb-4 flex-1">
                {scenario.description}
              </p>
              
              <button
                onClick={() => handleLaunch(scenario.name)}
                disabled={activeAttack !== null || demoRunning}
                className={`w-full py-1.5 rounded text-xs font-semibold uppercase tracking-wider flex items-center justify-center transition-colors ${
                  activeAttack === scenario.name
                    ? 'bg-red-500 text-white'
                    : 'bg-gray-800 text-gray-400 hover:bg-red-900/50 hover:text-red-400 border border-gray-700 hover:border-red-800'
                }`}
              >
                {activeAttack === scenario.name ? (
                  <><Loader size={14} className="mr-2 animate-spin" /> Injecting...</>
                ) : (
                  'Launch Attack'
                )}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Right side: Live Telemetry */}
      <div className="lg:w-1/3 bg-black border border-gray-800 rounded-lg flex flex-col overflow-hidden">
        <div className="p-3 border-b border-gray-800 bg-gray-900 flex items-center text-sm font-mono text-green-500">
          <Terminal size={16} className="mr-2" />
          Attack Telemetry
        </div>
        
        <div className="p-4 flex-1 overflow-y-auto font-mono text-xs text-gray-300 space-y-4">
          {simResult ? (
            <div className="animate-fade-in">
              <div className="text-blue-400 mb-2">&gt; Attack Payload Injected</div>
              
              <div className="pl-4 border-l border-gray-800 space-y-2">
                <div><span className="text-gray-500">Scenario:</span> {simResult.scenario}</div>
                <div><span className="text-gray-500">Target Layer:</span> {simResult.target_agent}</div>
                <div className="truncate"><span className="text-gray-500">Payload:</span> {JSON.stringify(simResult.payload_used)}</div>
              </div>

              <div className="text-blue-400 mt-4 mb-2">&gt; Mesh Response (Latency: {simResult.detection_latency_ms}ms)</div>
              
              <div className="pl-4 border-l border-gray-800 space-y-3">
                <div className="flex items-center">
                  <span className="text-gray-500 w-24">Detected:</span> 
                  {simResult.detected ? (
                    <span className="text-green-500 bg-green-500/10 px-2 py-0.5 rounded">YES</span>
                  ) : (
                    <span className="text-red-500 bg-red-500/10 px-2 py-0.5 rounded">NO</span>
                  )}
                </div>
                
                <div className="flex items-center">
                  <span className="text-gray-500 w-24">Blocked:</span> 
                  {simResult.blocked ? (
                    <span className="text-green-500 bg-green-500/10 px-2 py-0.5 rounded">YES</span>
                  ) : (
                    <span className="text-red-500 bg-red-500/10 px-2 py-0.5 rounded">NO</span>
                  )}
                </div>

                {simResult.detected && (
                  <div>
                    <span className="text-gray-500 w-24 inline-block">Caught By:</span>
                    <span className="text-purple-400">{simResult.security_layer_that_caught_it}</span>
                  </div>
                )}
                
                {simResult.recovery_triggered && (
                  <div className="flex items-center mt-2">
                    <ShieldAlert size={14} className="text-orange-500 mr-2 animate-pulse" />
                    <span className="text-orange-400">Self-Healing Recovery Triggered</span>
                  </div>
                )}
              </div>

              <div className="text-blue-400 mt-4 mb-2">&gt; Detailed Trace</div>
              <div className="pl-4 border-l border-gray-800 space-y-2 opacity-80 text-[10px]">
                {simResult.timeline?.map((t: any, i: number) => (
                  <div key={i} className="flex">
                    <span className="text-gray-600 w-12 shrink-0">+{t.time}ms</span>
                    <span className="text-gray-400">{t.event}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-gray-600 opacity-50">
              <Crosshair size={32} className="mb-4" />
              <p>Awaiting attack telemetry...</p>
              <p className="mt-2 text-[10px]">Select a scenario to begin</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
