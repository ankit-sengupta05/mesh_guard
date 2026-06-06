/**
 * StatsBar — Summary KPI cards across the top of the main content area.
 */

import { ShieldAlert, ShieldCheck, Activity, Users } from 'lucide-react'
import { useMeshStore } from '@/store/useMeshStore'

export function StatsBar() {
  const { stats } = useMeshStore()

  const metrics = [
    {
      label: 'Detection Rate',
      value: `${(stats.detection_rate * 100).toFixed(1)}%`,
      icon: Activity,
      color: 'text-mesh-info',
      bg: 'bg-mesh-info/10 border-mesh-info/20',
    },
    {
      label: 'Threats Blocked',
      value: stats.blocked_threats.toString(),
      icon: ShieldAlert,
      color: 'text-mesh-danger',
      bg: 'bg-mesh-danger/10 border-mesh-danger/20',
    },
    {
      label: 'Avg Trust Score',
      value: stats.avg_trust_score.toString(),
      icon: ShieldCheck,
      color: stats.avg_trust_score > 70 ? 'text-mesh-success' : 'text-mesh-warn',
      bg: stats.avg_trust_score > 70 ? 'bg-mesh-success/10 border-mesh-success/20' : 'bg-mesh-warn/10 border-mesh-warn/20',
    },
    {
      label: 'Active Agents',
      value: stats.active_agents.toString(),
      icon: Users,
      color: 'text-mesh-accent',
      bg: 'bg-mesh-accent/10 border-mesh-accent/20',
    },
  ]

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 md:gap-4 p-4 lg:p-6 pb-0 shrink-0">
      {metrics.map((m) => {
        const Icon = m.icon
        return (
          <div key={m.label} className="metric-card bg-mesh-surface/40 hover:bg-mesh-panel/80">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-mesh-text-dim">{m.label}</span>
              <div className={`p-1.5 rounded-lg border ${m.bg}`}>
                <Icon size={14} className={m.color} />
              </div>
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight text-mesh-text mt-1">
              {m.value}
            </div>
          </div>
        )
      })}
    </div>
  )
}
