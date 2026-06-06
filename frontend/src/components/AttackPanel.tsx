/**
 * AttackPanel — Red-team attack simulation control and results view.
 */

import { useState } from 'react'
import { Zap, ShieldAlert, Database, UserX, Wrench, PlayCircle, Loader2 } from 'lucide-react'
import { useApi } from '@/hooks/useApi'
import { useMeshStore, type AttackType, type AttackResult } from '@/store/useMeshStore'

const ATTACK_TYPES: { id: AttackType; label: string; icon: React.ElementType; desc: string }[] = [
  { id: 'prompt_injection', label: 'Prompt Injection', icon: ShieldAlert, desc: 'Adversarial payload targeting LLM firewall' },
  { id: 'memory_poison',    label: 'Memory Poison',    icon: Database,    desc: 'Attempt cross-namespace Redis write' },
  { id: 'identity_spoof',   label: 'Identity Spoof',   icon: UserX,       desc: 'Forge high-trust agent identity token' },
  { id: 'tool_hijack',      label: 'Tool Hijack',      icon: Wrench,      desc: 'Unauthorized MCP tool invocation' },
]

export function AttackPanel() {
  const { attackResults, clearAttackResults } = useMeshStore()
  const api = useApi()
  const [loading, setLoading] = useState<string | null>(null)

  const triggerAttack = async (type: AttackType) => {
    setLoading(type)
    try {
      await api.post('/api/v1/simulation/attack', { attack_type: type, intensity: 3 })
    } catch (err) {
      console.error('Attack failed', err)
    } finally {
      setLoading(null)
    }
  }

  const runScenario = async (scenario: string) => {
    setLoading('scenario')
    try {
      await api.post('/api/v1/simulation/scenario', { scenario_name: scenario, delay_between_attacks_ms: 800 })
    } catch (err) {
      console.error('Scenario failed', err)
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="flex flex-col h-full gap-4">
      {/* Header */}
      <div className="flex items-center justify-between glass-panel px-4 py-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-mesh-warn/20 border border-mesh-warn/30 flex items-center justify-center">
            <Zap size={16} className="text-mesh-warn" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-mesh-text">Attack Simulator</h2>
            <p className="text-xs text-mesh-text-dim">
              Red-team simulation against mesh defenses
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button onClick={() => runScenario('full_assault')} disabled={!!loading} className="btn-primary text-xs py-1.5 px-3 bg-mesh-danger hover:bg-mesh-danger/80">
            {loading === 'scenario' ? <Loader2 size={14} className="animate-spin" /> : <PlayCircle size={14} />}
            Full Assault
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 flex-1 min-h-0">
        
        {/* Controls Column */}
        <div className="flex flex-col gap-3 overflow-y-auto pr-1 scrollbar-thin">
          <h3 className="section-title">Attack Vectors</h3>
          
          {ATTACK_TYPES.map(attack => (
            <div key={attack.id} className="glass-panel p-4 flex flex-col gap-3 group hover:border-mesh-warn/30">
              <div className="flex items-start gap-3">
                <div className="p-2 bg-mesh-surface rounded-lg text-mesh-text-dim group-hover:text-mesh-warn transition-colors">
                  <attack.icon size={18} />
                </div>
                <div>
                  <h4 className="text-sm font-medium text-mesh-text">{attack.label}</h4>
                  <p className="text-[11px] text-mesh-text-dim mt-0.5">{attack.desc}</p>
                </div>
              </div>
              <button 
                onClick={() => triggerAttack(attack.id)}
                disabled={!!loading}
                className="w-full btn-ghost text-xs justify-center py-1.5 mt-1 border-mesh-border/50 group-hover:border-mesh-warn/30 group-hover:text-mesh-warn"
              >
                {loading === attack.id ? <Loader2 size={14} className="animate-spin" /> : 'Launch Payload'}
              </button>
            </div>
          ))}
        </div>

        {/* Results Column */}
        <div className="lg:col-span-2 flex flex-col gap-3 h-full overflow-hidden">
          <div className="flex items-center justify-between">
            <h3 className="section-title">Simulation Results</h3>
            {attackResults.length > 0 && (
              <button onClick={clearAttackResults} className="text-[10px] text-mesh-text-dim hover:text-mesh-text underline underline-offset-2">
                Clear log
              </button>
            )}
          </div>
          
          <div className="flex-1 glass-panel overflow-y-auto scrollbar-thin p-1">
            {attackResults.length === 0 ? (
               <div className="h-full flex flex-col items-center justify-center text-mesh-text-dim">
                 <Zap size={32} className="opacity-20 mb-3" />
                 <p className="text-sm">Awaiting simulation events.</p>
               </div>
            ) : (
              <div className="flex flex-col gap-2 p-2">
                {attackResults.map((res: AttackResult, i: number) => (
                  <div key={`${res.attack_id}-${i}`} className={`p-3 rounded-lg border flex flex-col gap-2 ${res.blocked ? 'bg-mesh-success/5 border-mesh-success/20' : 'bg-mesh-danger/10 border-mesh-danger/30'}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {res.blocked ? (
                          <span className="badge-success text-[10px] uppercase">Defended</span>
                        ) : (
                          <span className="badge-danger text-[10px] uppercase animate-pulse">Breached</span>
                        )}
                        <span className="text-xs font-semibold capitalize text-mesh-text">
                          {res.attack_type.replace('_', ' ')}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-mesh-text-dim">{res.duration_ms}ms</span>
                    </div>
                    
                    <div className="font-mono text-[10px] text-mesh-text-dim bg-black/40 p-2 rounded border border-white/5 truncate" title={res.payload_used}>
                      <span className="text-mesh-warn/50 mr-2">payload:</span>
                      {res.payload_used}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  )
}
