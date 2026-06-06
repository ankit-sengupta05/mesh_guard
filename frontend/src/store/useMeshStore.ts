/**
 * AgentOps Security Mesh — Zustand Global Store
 *
 * Manages all real-time application state:
 * - WebSocket connection lifecycle
 * - Threat events feed
 * - Agent registry
 * - Trust topology
 * - Attack simulation results
 * - System stats
 */

import { create } from 'zustand'
import { devtools } from 'zustand/middleware'

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type AgentStatus = 'idle' | 'running' | 'paused' | 'quarantined' | 'terminated' | 'failed'
export type AgentRole = 'planner' | 'web' | 'code' | 'api' | 'memory' | 'monitor'
export type AttackType = 'prompt_injection' | 'memory_poison' | 'identity_spoof' | 'tool_hijack'

export interface ThreatEvent {
  event_id: string
  type: string
  severity: Severity
  blocked: boolean
  confidence: number
  agent_id: string | null
  prompt_excerpt: string
  matched_patterns: string[]
  timestamp: string
}

export interface Agent {
  agent_id: string
  name: string
  role: AgentRole
  status: AgentStatus
  trust_score: number
  description: string | null
  metadata: Record<string, unknown>
  registered_at: string
  last_active: string | null
}

export interface TrustNode {
  id: string
  name: string
  role: AgentRole
  status: AgentStatus
  trust_score: number
  quarantined: boolean
}

export interface TrustEdge {
  id: string
  source: string
  target: string
  type: string
  trust_weight: number
}

export interface AttackResult {
  attack_id: string
  attack_type: AttackType
  target_agent_id: string | null
  payload_used: string
  detected: boolean
  blocked: boolean
  severity: string
  confidence: number
  timestamp: string
  duration_ms: number
}

export interface SystemStats {
  total_threats: number
  blocked_threats: number
  active_agents: number
  avg_trust_score: number
  detection_rate: number
  ws_connections: number
}

export type WsStatus = 'connecting' | 'connected' | 'disconnected' | 'error'

// ─────────────────────────────────────────────────────────────────────────────
// Store interface
// ─────────────────────────────────────────────────────────────────────────────

export interface MeshStore {
  // Connection state
  wsStatus: WsStatus
  setWsStatus: (s: WsStatus) => void

  // Threat feed (ring buffer — max 200 events)
  threats: ThreatEvent[]
  addThreat: (t: ThreatEvent) => void
  clearThreats: () => void

  // Agents
  agents: Agent[]
  setAgents: (agents: Agent[]) => void
  upsertAgent: (agent: Agent) => void
  updateAgentStatus: (agent_id: string, status: AgentStatus) => void

  // Trust graph
  trustNodes: TrustNode[]
  trustEdges: TrustEdge[]
  setTrustTopology: (nodes: TrustNode[], edges: TrustEdge[]) => void

  // Attack results
  attackResults: AttackResult[]
  addAttackResult: (r: AttackResult) => void
  clearAttackResults: () => void

  // System stats
  stats: SystemStats
  updateStats: (partial: Partial<SystemStats>) => void

  // UI state
  selectedAgentId: string | null
  setSelectedAgent: (id: string | null) => void
  activeTab: 'threats' | 'agents' | 'trust' | 'attacks' | 'recovery'
  setActiveTab: (tab: MeshStore['activeTab']) => void
  isSettingsOpen: boolean
  setSettingsOpen: (isOpen: boolean) => void
}

// ─────────────────────────────────────────────────────────────────────────────
// Store implementation
// ─────────────────────────────────────────────────────────────────────────────

const MAX_THREATS = 200
const MAX_ATTACKS = 100

export const useMeshStore = create<MeshStore>()(
  devtools(
    (set, get) => ({
      // ── WebSocket ──────────────────────────────────────────────────────────
      wsStatus: 'disconnected',
      setWsStatus: (wsStatus: WsStatus) => set({ wsStatus }, false, 'setWsStatus'),

      // ── Threats ───────────────────────────────────────────────────────────
      threats: [],
      addThreat: (t: ThreatEvent) =>
        set(
          (state) => ({
            threats: [t, ...state.threats].slice(0, MAX_THREATS),
            stats: {
              ...state.stats,
              total_threats: state.stats.total_threats + 1,
              blocked_threats: state.stats.blocked_threats + (t.blocked ? 1 : 0),
              detection_rate: Math.min(
                1,
                (state.stats.blocked_threats + (t.blocked ? 1 : 0)) /
                  (state.stats.total_threats + 1),
              ),
            },
          }),
          false,
          'addThreat',
        ),
      clearThreats: () => set({ threats: [] }, false, 'clearThreats'),

      // ── Agents ────────────────────────────────────────────────────────────
      agents: [],
      setAgents: (agents: Agent[]) =>
        set(
          (state) => ({ agents, stats: { ...state.stats, active_agents: agents.length } }),
          false,
          'setAgents',
        ),
      upsertAgent: (agent: Agent) =>
        set(
          (state) => {
            const idx = state.agents.findIndex((a) => a.agent_id === agent.agent_id)
            const next =
              idx >= 0
                ? state.agents.map((a, i) => (i === idx ? agent : a))
                : [...state.agents, agent]
            return { agents: next, stats: { ...state.stats, active_agents: next.length } }
          },
          false,
          'upsertAgent',
        ),
      updateAgentStatus: (agent_id: string, status: AgentStatus) =>
        set(
          (state) => ({
            agents: state.agents.map((a) =>
              a.agent_id === agent_id ? { ...a, status } : a,
            ),
          }),
          false,
          'updateAgentStatus',
        ),

      // ── Trust graph ───────────────────────────────────────────────────────
      trustNodes: [],
      trustEdges: [],
      setTrustTopology: (trustNodes: TrustNode[], trustEdges: TrustEdge[]) =>
        set(
          (state) => ({
            trustNodes,
            trustEdges,
            stats: {
              ...state.stats,
              avg_trust_score:
                trustNodes.length > 0
                  ? Math.round(
                      trustNodes.reduce((s, n) => s + n.trust_score, 0) / trustNodes.length,
                    )
                  : 0,
            },
          }),
          false,
          'setTrustTopology',
        ),

      // ── Attacks ───────────────────────────────────────────────────────────
      attackResults: [],
      addAttackResult: (r: AttackResult) =>
        set(
          (state) => ({ attackResults: [r, ...state.attackResults].slice(0, MAX_ATTACKS) }),
          false,
          'addAttackResult',
        ),
      clearAttackResults: () => set({ attackResults: [] }, false, 'clearAttackResults'),

      // ── Stats ─────────────────────────────────────────────────────────────
      stats: {
        total_threats: 0,
        blocked_threats: 0,
        active_agents: 0,
        avg_trust_score: 80,
        detection_rate: 0,
        ws_connections: 0,
      },
      updateStats: (partial: Partial<SystemStats>) =>
        set(
          (state) => ({ stats: { ...state.stats, ...partial } }),
          false,
          'updateStats',
        ),

      // ── UI ────────────────────────────────────────────────────────────────
      selectedAgentId: null,
      setSelectedAgent: (selectedAgentId: string | null) =>
        set({ selectedAgentId }, false, 'setSelectedAgent'),
      activeTab: 'threats',
      setActiveTab: (activeTab: MeshStore['activeTab']) => set({ activeTab }, false, 'setActiveTab'),
      isSettingsOpen: false,
      setSettingsOpen: (isSettingsOpen: boolean) => set({ isSettingsOpen }, false, 'setSettingsOpen'),
    }),
    { name: 'AgentOpsMesh' },
  ),
)
