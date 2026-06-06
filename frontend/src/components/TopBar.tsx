/**
 * TopBar — Application header with branding, WS status, and live indicator.
 */

import { Shield, Wifi, WifiOff, AlertTriangle, Loader2 } from 'lucide-react'
import { useMeshStore, type ThreatEvent } from '@/store/useMeshStore'

const WS_STATUS_CONFIG = {
  connected:    { icon: Wifi,          color: 'text-mesh-success', label: 'Connected',    dot: 'bg-mesh-success' },
  connecting:   { icon: Loader2,       color: 'text-mesh-warn animate-spin', label: 'Connecting…', dot: 'bg-mesh-warn' },
  disconnected: { icon: WifiOff,       color: 'text-mesh-muted',   label: 'Disconnected', dot: 'bg-mesh-muted' },
  error:        { icon: AlertTriangle, color: 'text-mesh-danger',  label: 'Error',        dot: 'bg-mesh-danger' },
}

export function TopBar() {
  const { wsStatus, threats, stats } = useMeshStore()
  const ws = WS_STATUS_CONFIG[wsStatus as keyof typeof WS_STATUS_CONFIG]
  const WsIcon = ws.icon

  const criticalCount = threats.filter((t: ThreatEvent) => t.severity === 'critical' && !t.blocked).length

  return (
    <header className="h-14 flex items-center justify-between px-4 lg:px-6 border-b border-mesh-border bg-mesh-surface/60 backdrop-blur-xl z-20 shrink-0">
      {/* Brand */}
      <div className="flex items-center gap-3">
        <div className="relative">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-mesh-accent to-mesh-accent-2 flex items-center justify-center shadow-glow-accent">
            <Shield size={16} className="text-white" />
          </div>
          {criticalCount > 0 && (
            <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-mesh-danger text-[9px] font-bold text-white flex items-center justify-center animate-pulse">
              {criticalCount}
            </span>
          )}
        </div>
        <div>
          <div className="text-sm font-bold tracking-tight text-gradient-accent">
            AgentOps Security Mesh
          </div>
          <div className="text-[10px] text-mesh-text-dim font-mono leading-none">
            v1.0.0 · AI Security OS
          </div>
        </div>
      </div>

      {/* Right side status */}
      <div className="flex items-center gap-4">
        {/* Agent count */}
        <div className="hidden sm:flex items-center gap-1.5 text-xs text-mesh-text-dim">
          <span className="font-mono font-semibold text-mesh-text">{stats.active_agents}</span>
          <span>agents</span>
        </div>

        {/* Threat count */}
        <div className="hidden sm:flex items-center gap-1.5 text-xs text-mesh-text-dim">
          <span className="font-mono font-semibold text-mesh-danger">{stats.blocked_threats}</span>
          <span>blocked</span>
        </div>

        {/* WS status */}
        <div className={`flex items-center gap-1.5 text-xs ${ws.color}`}>
          <WsIcon size={13} />
          <span className="hidden md:inline font-medium">{ws.label}</span>
          <span className={`w-1.5 h-1.5 rounded-full ${ws.dot} ${wsStatus === 'connected' ? 'animate-pulse' : ''}`} />
        </div>
      </div>
    </header>
  )
}
