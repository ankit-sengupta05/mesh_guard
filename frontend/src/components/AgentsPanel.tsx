/**
 * AgentsPanel — List of active agents, their roles, status, and trust scores.
 */

import { Bot, Play, Pause, XCircle, ShieldOff } from 'lucide-react'
import { useMeshStore, type Agent } from '@/store/useMeshStore'
import { useApi } from '@/hooks/useApi'

export function AgentsPanel() {
  const { agents } = useMeshStore()

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="flex items-center justify-between glass-panel px-4 py-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-mesh-accent/20 border border-mesh-accent/30 flex items-center justify-center">
            <Bot size={16} className="text-mesh-accent" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-mesh-text">Agent Registry</h2>
            <p className="text-xs text-mesh-text-dim">
              Active swarm members and their trust state
            </p>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        {agents.length === 0 ? (
          <div className="h-full glass-panel flex items-center justify-center text-mesh-text-dim">
            No agents registered yet.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {agents.map((agent: Agent) => (
              <AgentCard key={agent.agent_id} agent={agent} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function AgentCard({ agent }: { agent: Agent }) {
  const api = useApi()

  const handleAction = async (action: 'pause' | 'resume' | 'terminate' | 'quarantine') => {
    try {
      await api.post(`/api/v1/agents/${agent.agent_id}/control`, { action, reason: 'Manual dashboard override' })
    } catch (err) {
      console.error('Failed to control agent', err)
    }
  }

  const isHighTrust = agent.trust_score > 80
  const isQuarantined = agent.status === 'quarantined'
  const isTerminated = agent.status === 'terminated'

  return (
    <div className={`
      glass-panel p-4 flex flex-col gap-4 relative overflow-hidden transition-all
      ${isQuarantined ? 'border-mesh-danger/40 bg-mesh-danger/5 shadow-[0_0_15px_rgba(239,68,68,0.1)]' : ''}
      ${isTerminated ? 'opacity-50 grayscale' : 'hover:border-mesh-accent/30'}
    `}>
      {/* Background role badge */}
      <div className="absolute -top-4 -right-4 text-8xl opacity-[0.03] pointer-events-none font-bold uppercase select-none">
        {agent.role}
      </div>

      {/* Header */}
      <div className="flex items-start justify-between relative z-10">
        <div>
          <h3 className="text-base font-semibold text-mesh-text flex items-center gap-2">
            {agent.name}
            {agent.status === 'running' && <span className="live-dot" />}
          </h3>
          <p className="text-xs text-mesh-text-dim font-mono mt-0.5">
            {agent.agent_id.substring(0, 12)}...
          </p>
        </div>
        <StatusBadge status={agent.status} />
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 gap-2 bg-black/20 p-2.5 rounded-lg border border-white/5 relative z-10">
        <div className="flex flex-col">
          <span className="text-[10px] text-mesh-text-dim uppercase tracking-wider mb-0.5">Role</span>
          <span className="text-sm font-medium text-mesh-text capitalize">{agent.role}</span>
        </div>
        <div className="flex flex-col">
          <span className="text-[10px] text-mesh-text-dim uppercase tracking-wider mb-0.5 flex items-center gap-1">
            Trust Score
            {isQuarantined && <ShieldOff size={10} className="text-mesh-danger" />}
          </span>
          <div className="flex items-end gap-1.5">
            <span className={`text-lg font-bold font-mono leading-none ${isQuarantined ? 'text-mesh-danger' : isHighTrust ? 'text-mesh-success' : 'text-mesh-warn'}`}>
              {agent.trust_score.toFixed(0)}
            </span>
            <span className="text-[10px] text-mesh-text-dim mb-0.5">/100</span>
          </div>
        </div>
      </div>

      {/* Description */}
      {agent.description && (
        <p className="text-xs text-mesh-text-dim line-clamp-2 relative z-10">
          {agent.description}
        </p>
      )}

      {/* Controls */}
      {!isTerminated && (
        <div className="flex gap-2 mt-auto pt-2 relative z-10">
          {(agent.status === 'running' || agent.status === 'idle') && (
            <button onClick={() => handleAction('pause')} className="flex-1 btn-ghost text-xs py-1.5 bg-mesh-surface justify-center" title="Pause Execution">
              <Pause size={14} /> Pause
            </button>
          )}
          {agent.status === 'paused' && (
            <button onClick={() => handleAction('resume')} className="flex-1 btn-ghost text-xs py-1.5 bg-mesh-surface justify-center text-mesh-success hover:bg-mesh-success/10 hover:text-mesh-success hover:border-mesh-success/30" title="Resume">
              <Play size={14} /> Resume
            </button>
          )}
          {!isQuarantined && (
            <button onClick={() => handleAction('quarantine')} className="flex-1 btn-ghost text-xs py-1.5 bg-mesh-surface justify-center text-mesh-warn hover:bg-mesh-warn/10 hover:text-mesh-warn hover:border-mesh-warn/30" title="Force Quarantine">
              <ShieldOff size={14} /> Block
            </button>
          )}
          <button onClick={() => handleAction('terminate')} className="w-10 flex-shrink-0 btn-ghost text-xs py-1.5 bg-mesh-surface justify-center text-mesh-danger hover:bg-mesh-danger/10 hover:text-mesh-danger hover:border-mesh-danger/30" title="Terminate">
            <XCircle size={14} />
          </button>
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  switch (status) {
    case 'running':     return <span className="badge-success uppercase">Running</span>
    case 'idle':        return <span className="badge-info uppercase">Idle</span>
    case 'paused':      return <span className="badge-warn uppercase">Paused</span>
    case 'quarantined': return <span className="badge-danger uppercase">Quarantined</span>
    case 'failed':      return <span className="badge-danger uppercase bg-red-900/50">Failed</span>
    case 'terminated':  return <span className="badge-muted uppercase">Terminated</span>
    default:            return <span className="badge-muted uppercase">{status}</span>
  }
}
