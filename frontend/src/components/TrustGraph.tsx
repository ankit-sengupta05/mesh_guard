/**
 * TrustGraph — D3-style network visualization of agents and their trust relationships.
 * Uses Recharts scatter plot as a lightweight force-graph alternative.
 */

import { useMemo } from 'react'
import { ScatterChart, Scatter, XAxis, YAxis, ZAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { Network, ShieldAlert } from 'lucide-react'
import { useMeshStore, type TrustNode } from '@/store/useMeshStore'

export function TrustGraph() {
  const { trustNodes, trustEdges } = useMeshStore()

  // Generate deterministic positions for nodes to simulate a force layout
  const graphData = useMemo(() => {
    if (trustNodes.length === 0) return []

    // Center planner
    const plannerNode = trustNodes.find((n: TrustNode) => n.role === 'planner')
    const executors = trustNodes.filter((n: TrustNode) => n.role !== 'planner')

    const data = []

    if (plannerNode) {
      data.push({
        ...plannerNode,
        x: 50,
        y: 50,
        z: 100, // Size
        fill: plannerNode.quarantined ? '#ef4444' : '#6366f1',
      })
    }

    // Distribute executors in a circle around the planner
    const radius = 30
    executors.forEach((node: TrustNode, i: number) => {
      const angle = (i / Math.max(1, executors.length)) * 2 * Math.PI
      const cx = 50 + radius * Math.cos(angle)
      const cy = 50 + radius * Math.sin(angle)

      data.push({
        ...node,
        x: cx,
        y: cy,
        z: 60,
        fill: node.quarantined ? '#ef4444' : node.trust_score > 70 ? '#10b981' : '#f59e0b',
      })
    })

    return data
  }, [trustNodes])

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="flex items-center justify-between glass-panel px-4 py-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-mesh-info/20 border border-mesh-info/30 flex items-center justify-center">
            <Network size={16} className="text-mesh-info" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-mesh-text">Trust Topology</h2>
            <p className="text-xs text-mesh-text-dim">
              Agent interaction graph and permission edges (Neo4j)
            </p>
          </div>
        </div>
      </div>

      <div className="flex-1 glass-panel relative overflow-hidden flex items-center justify-center">
        {trustNodes.length === 0 ? (
          <div className="text-mesh-text-dim flex flex-col items-center">
            <Network size={32} className="opacity-20 mb-3" />
            <p className="text-sm">Graph is empty.</p>
            <p className="text-xs opacity-60">Register agents to see topology.</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
              <XAxis type="number" dataKey="x" domain={[0, 100]} hide />
              <YAxis type="number" dataKey="y" domain={[0, 100]} hide />
              <ZAxis type="number" dataKey="z" range={[200, 1000]} />
              <Tooltip content={<CustomTooltip />} cursor={{ strokeDasharray: '3 3' }} />
              <Scatter data={graphData} shape="circle">
                {graphData.map((entry: any, index: number) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} stroke={entry.quarantined ? '#ef4444' : '#1e1e2e'} strokeWidth={2} />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        )}

        {/* Legend overlay */}
        <div className="absolute bottom-4 left-4 glass-panel p-3 bg-mesh-surface/90">
          <div className="text-[10px] uppercase font-bold text-mesh-text-dim mb-2 tracking-wider">Legend</div>
          <div className="flex flex-col gap-1.5 text-xs">
            <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-mesh-accent border border-mesh-border" /> Planner / Orchestrator</div>
            <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-mesh-success border border-mesh-border" /> Trusted Executor</div>
            <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-mesh-warn border border-mesh-border" /> Degraded Trust</div>
            <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-mesh-danger border-2 border-mesh-danger/50 shadow-glow-danger" /> Quarantined Node</div>
          </div>
        </div>
      </div>
    </div>
  )
}

function CustomTooltip({ active, payload }: any) {
  if (active && payload && payload.length) {
    const data = payload[0].payload
    return (
      <div className="glass-panel p-3 min-w-48 bg-mesh-panel/95 backdrop-blur-md">
        <div className="flex items-center gap-2 mb-1">
          {data.quarantined && <ShieldAlert size={14} className="text-mesh-danger" />}
          <span className="font-bold text-sm text-mesh-text">{data.name}</span>
        </div>
        <div className="text-xs text-mesh-text-dim font-mono mb-2">{data.id}</div>

        <div className="grid grid-cols-2 gap-2 mt-2 pt-2 border-t border-mesh-border">
          <div>
            <div className="text-[10px] text-mesh-text-dim uppercase">Role</div>
            <div className="text-xs font-medium capitalize">{data.role}</div>
          </div>
          <div>
            <div className="text-[10px] text-mesh-text-dim uppercase">Score</div>
            <div className={`text-xs font-bold font-mono ${data.quarantined ? 'text-mesh-danger' : data.trust_score > 70 ? 'text-mesh-success' : 'text-mesh-warn'}`}>
              {data.trust_score.toFixed(0)}/100
            </div>
          </div>
        </div>
      </div>
    )
  }
  return null
}
