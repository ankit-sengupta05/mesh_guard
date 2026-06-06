/**
 * Sidebar — Tab navigation for the security dashboard.
 */

import { Shield, Bot, Network, Zap, RotateCcw } from 'lucide-react'
import { useMeshStore } from '@/store/useMeshStore'
import type { MeshStore } from '@/store/useMeshStore'
import { clsx } from 'clsx'

type Tab = MeshStore['activeTab']

const NAV_ITEMS: { tab: Tab; label: string; icon: React.ElementType; badgeKey?: keyof MeshStore['stats'] }[] = [
  { tab: 'threats',  label: 'Threats',   icon: Shield,    badgeKey: 'blocked_threats' },
  { tab: 'agents',   label: 'Agents',    icon: Bot,       badgeKey: 'active_agents' },
  { tab: 'trust',    label: 'Trust',     icon: Network },
  { tab: 'attacks',  label: 'Sim',       icon: Zap },
  { tab: 'recovery', label: 'Recovery',  icon: RotateCcw },
]

export function Sidebar() {
  const { activeTab, setActiveTab, stats } = useMeshStore()

  return (
    <nav className="w-16 lg:w-52 shrink-0 flex flex-col border-r border-mesh-border bg-mesh-surface/40 backdrop-blur-xl">
      <div className="flex-1 py-4 flex flex-col gap-1 px-2">
        {NAV_ITEMS.map(({ tab, label, icon: Icon, badgeKey }) => {
          const isActive = activeTab === tab
          const badgeVal = badgeKey ? (stats[badgeKey] as number) : null

          return (
            <button
              key={tab}
              id={`nav-${tab}`}
              onClick={() => setActiveTab(tab)}
              className={clsx(
                'group flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150',
                isActive
                  ? 'bg-mesh-accent/15 text-mesh-accent border border-mesh-accent/25 shadow-glow-accent'
                  : 'text-mesh-text-dim hover:text-mesh-text hover:bg-mesh-panel',
              )}
            >
              <Icon
                size={17}
                className={clsx(
                  'shrink-0 transition-transform duration-150',
                  isActive && 'text-mesh-accent',
                  !isActive && 'group-hover:scale-110',
                )}
              />
              <span className="hidden lg:inline truncate">{label}</span>
              {badgeVal != null && badgeVal > 0 && (
                <span
                  className={clsx(
                    'hidden lg:flex ml-auto min-w-5 h-5 items-center justify-center rounded-full text-[10px] font-bold px-1',
                    tab === 'threats'
                      ? 'bg-mesh-danger/20 text-mesh-danger'
                      : 'bg-mesh-accent/20 text-mesh-accent',
                  )}
                >
                  {badgeVal > 99 ? '99+' : badgeVal}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* Bottom version tag */}
      <div className="p-3 border-t border-mesh-border">
        <div className="hidden lg:block text-[10px] text-mesh-text-dim font-mono text-center">
          Security OS v1.0
        </div>
      </div>
    </nav>
  )
}
