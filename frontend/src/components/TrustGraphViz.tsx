import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';

export interface TrustGraphNode extends d3.SimulationNodeDatum {
  id: string;
  name: string;
  role: string;
  trust_score: number;
  status: string;
}

export interface TrustGraphLink extends d3.SimulationLinkDatum<TrustGraphNode> {
  source: string | TrustGraphNode;
  target: string | TrustGraphNode;
  type: string;
  interaction_count?: number;
}

interface TrustGraphVizProps {
  nodes: TrustGraphNode[];
  links: TrustGraphLink[];
}

const ROLE_COLORS: Record<string, string> = {
  planner:   '#6366f1',
  PLANNER:   '#6366f1',
  executor:  '#10b981',
  EXECUTOR:  '#10b981',
  validator: '#f59e0b',
  VALIDATOR: '#f59e0b',
  sentinel:  '#ef4444',
  SENTINEL:  '#ef4444',
  monitor:   '#06b6d4',
  MONITOR:   '#06b6d4',
  web:       '#10b981',
  code:      '#10b981',
  api:       '#10b981',
  memory:    '#10b981',
};

function nodeColor(d: TrustGraphNode): string {
  if (d.status === 'SUSPENDED') return '#374151';
  return ROLE_COLORS[d.role] ?? '#6b7280';
}

function ringColor(d: TrustGraphNode): string {
  if (d.status === 'SUSPENDED') return '#374151';
  if (d.trust_score > 0.8) return '#22c55e';
  if (d.trust_score > 0.4) return '#eab308';
  return '#ef4444';
}

export const TrustGraphViz: React.FC<TrustGraphVizProps> = ({ nodes, links }) => {
  const svgRef    = useRef<SVGSVGElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const simRef    = useRef<d3.Simulation<TrustGraphNode, TrustGraphLink> | null>(null);
  const [selected, setSelected] = useState<TrustGraphNode | null>(null);
  const [dims, setDims] = useState({ w: 800, h: 500 });

  // Observe container resize so the simulation always fills the available space
  useEffect(() => {
    const el = wrapperRef.current;
    if (!el) return;
    const ro = new ResizeObserver(entries => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        if (width > 0 && height > 0) setDims({ w: width, h: height });
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const buildGraph = useCallback(() => {
    if (!svgRef.current || nodes.length === 0) return;
    const { w, h } = dims;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // ── Defs: arrow marker ──────────────────────────────────────────────────
    const defs = svg.append('defs');
    defs.append('marker')
      .attr('id', 'tg-arrow')
      .attr('viewBox', '0 -4 8 8')
      .attr('refX', 26)
      .attr('refY', 0)
      .attr('markerWidth', 5)
      .attr('markerHeight', 5)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L8,0L0,4')
      .attr('fill', '#4b5563');

    // ── Root group with zoom/pan ────────────────────────────────────────────
    const root = svg.append('g').attr('class', 'root');
    svg.call(
      d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.3, 3])
        .on('zoom', (event) => root.attr('transform', event.transform))
    );

    // Deep-copy nodes so D3 can mutate x/y without touching React state
    const simNodes: TrustGraphNode[] = nodes.map(d => ({ ...d }));

    // Resolve link source/target to indices so forceLink works
    const idIndex = new Map(simNodes.map((d, i) => [d.id, i]));
    const simLinks: TrustGraphLink[] = links.map(l => ({
      ...l,
      source: typeof l.source === 'string' ? l.source : (l.source as TrustGraphNode).id,
      target: typeof l.target === 'string' ? l.target : (l.target as TrustGraphNode).id,
    })).filter(l =>
      idIndex.has(l.source as string) && idIndex.has(l.target as string)
    );

    // ── Simulation ──────────────────────────────────────────────────────────
    const sim = d3.forceSimulation<TrustGraphNode>(simNodes)
      .force('link',    d3.forceLink<TrustGraphNode, TrustGraphLink>(simLinks)
                          .id(d => d.id)
                          .distance(120)
                          .strength(0.5))
      .force('charge',  d3.forceManyBody().strength(-400))
      .force('center',  d3.forceCenter(w / 2, h / 2))
      .force('collide', d3.forceCollide<TrustGraphNode>().radius(48).strength(0.8))
      .alphaDecay(0.02);

    simRef.current = sim;

    // ── Links ───────────────────────────────────────────────────────────────
    const linkG = root.append('g').attr('class', 'links');
    const link = linkG.selectAll<SVGLineElement, TrustGraphLink>('line')
      .data(simLinks)
      .join('line')
      .attr('stroke', '#374151')
      .attr('stroke-opacity', 0.7)
      .attr('stroke-width', d => Math.max(1, Math.min(4, ((d.interaction_count ?? 1) * 0.5))))
      .attr('marker-end', 'url(#tg-arrow)');

    // ── Nodes ───────────────────────────────────────────────────────────────
    const nodeG = root.append('g').attr('class', 'nodes');
    const node = nodeG.selectAll<SVGGElement, TrustGraphNode>('g')
      .data(simNodes)
      .join('g')
      .attr('cursor', 'grab')
      .call(
        d3.drag<SVGGElement, TrustGraphNode>()
          .on('start', (event, d) => {
            if (!event.active) sim.alphaTarget(0.3).restart();
            d.fx = d.x; d.fy = d.y;
          })
          .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
          .on('end',  (event, d) => {
            if (!event.active) sim.alphaTarget(0);
            d.fx = null; d.fy = null;
          })
      )
      .on('click', (_event, d) => {
        setSelected(prev => prev?.id === d.id ? null : d);
      });

    // Outer glow ring (trust indicator)
    node.append('circle')
      .attr('r', 26)
      .attr('fill', 'none')
      .attr('stroke', d => ringColor(d))
      .attr('stroke-width', 3)
      .attr('stroke-dasharray', d => {
        const circ = 2 * Math.PI * 26;
        return `${(d.trust_score ?? 1) * circ} ${circ}`;
      })
      .attr('transform', 'rotate(-90)');

    // Inner filled circle
    node.append('circle')
      .attr('r', 20)
      .attr('fill', d => nodeColor(d))
      .attr('fill-opacity', 0.85)
      .attr('stroke', '#0f172a')
      .attr('stroke-width', 2);

    // Pulse ring for RECOVERING / SUSPENDED
    node.filter(d => d.status === 'RECOVERING' || d.status === 'SUSPENDED')
      .append('circle')
      .attr('r', 26)
      .attr('fill', 'none')
      .attr('stroke', d => d.status === 'RECOVERING' ? '#ef4444' : '#374151')
      .attr('stroke-width', 2)
      .style('opacity', 0.8)
      .each(function pulse(this: SVGCircleElement) {
        d3.select(this)
          .transition().duration(1200).ease(d3.easeSinInOut)
          .attr('r', 38).style('opacity', 0)
          .transition().duration(0)
          .attr('r', 26).style('opacity', 0.8)
          .on('end', pulse);
      });

    // Initial letter icon
    node.append('text')
      .attr('dy', 5)
      .attr('text-anchor', 'middle')
      .attr('fill', '#f9fafb')
      .attr('font-size', '13px')
      .attr('font-weight', 'bold')
      .attr('font-family', 'monospace')
      .attr('pointer-events', 'none')
      .text(d => (d.name || d.id || '?').charAt(0).toUpperCase());

    // Name label below node
    node.append('text')
      .attr('dy', 42)
      .attr('text-anchor', 'middle')
      .attr('fill', '#d1d5db')
      .attr('font-size', '11px')
      .attr('font-weight', '600')
      .attr('pointer-events', 'none')
      .text(d => d.name || d.id);

    // Role badge below name
    node.append('text')
      .attr('dy', 55)
      .attr('text-anchor', 'middle')
      .attr('fill', '#6b7280')
      .attr('font-size', '9px')
      .attr('font-family', 'monospace')
      .attr('pointer-events', 'none')
      .text(d => (d.role || '').toUpperCase());

    // Trust score arc label
    node.append('text')
      .attr('dy', -30)
      .attr('text-anchor', 'middle')
      .attr('fill', d => ringColor(d))
      .attr('font-size', '9px')
      .attr('font-family', 'monospace')
      .attr('pointer-events', 'none')
      .text(d => `${Math.round((d.trust_score ?? 1) * 100)}%`);

    // ── Tick ────────────────────────────────────────────────────────────────
    sim.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);
      node.attr('transform', (d: any) => `translate(${d.x ?? 0},${d.y ?? 0})`);
    });

  }, [nodes, links, dims]);

  // Rebuild whenever nodes/links/dims change
  useEffect(() => {
    buildGraph();
    return () => { simRef.current?.stop(); };
  }, [buildGraph]);

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg h-full flex flex-col overflow-hidden relative">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 bg-gray-950/60 shrink-0">
        <h2 className="text-base font-semibold text-gray-200">Trust Graph Visualization</h2>
        <div className="flex items-center gap-4 text-xs font-mono text-gray-500">
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full border-2 border-green-500 inline-block" /> Safe</span>
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full border-2 border-yellow-500 inline-block" /> Warn</span>
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full border-2 border-red-500 inline-block" /> Critical</span>
          <span className="text-gray-600">Drag • Scroll to zoom</span>
        </div>
      </div>

      {/* Graph area */}
      <div ref={wrapperRef} className="flex-1 w-full relative overflow-hidden">
        {nodes.length === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-gray-600 gap-3">
            <svg xmlns="http://www.w3.org/2000/svg" className="opacity-20" width={48} height={48} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}><circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><line x1="12" y1="8" x2="5" y2="16"/><line x1="12" y1="8" x2="19" y2="16"/></svg>
            <p className="text-sm">No agents in graph yet.</p>
            <p className="text-xs opacity-60">Agents register automatically on startup.</p>
          </div>
        ) : (
          <svg ref={svgRef} width="100%" height="100%" />
        )}

        {/* Selected node info panel */}
        {selected && (
          <div
            className="absolute bottom-4 right-4 bg-gray-950/95 border border-gray-700 rounded-lg p-4 w-56 shadow-xl"
            style={{ backdropFilter: 'blur(8px)' }}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="font-bold text-sm text-blue-400">{selected.name}</span>
              <button onClick={() => setSelected(null)} className="text-gray-500 hover:text-gray-300 text-xs">✕</button>
            </div>
            <div className="text-xs font-mono text-gray-400 mb-3 truncate">{selected.id}</div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <div className="text-gray-500 uppercase text-[10px] mb-0.5">Role</div>
                <div className="text-gray-200 capitalize">{selected.role}</div>
              </div>
              <div>
                <div className="text-gray-500 uppercase text-[10px] mb-0.5">Trust</div>
                <div className="font-bold font-mono" style={{ color: ringColor(selected) }}>
                  {Math.round((selected.trust_score ?? 1) * 100)}%
                </div>
              </div>
              <div className="col-span-2">
                <div className="text-gray-500 uppercase text-[10px] mb-0.5">Status</div>
                <div className={`font-medium ${selected.status === 'ACTIVE' ? 'text-green-400' : selected.status === 'SUSPENDED' ? 'text-gray-400' : 'text-red-400'}`}>
                  {selected.status}
                </div>
              </div>
            </div>
            {/* Trust bar */}
            <div className="mt-3">
              <div className="w-full bg-gray-800 rounded-full h-1.5">
                <div
                  className="h-1.5 rounded-full transition-all"
                  style={{
                    width: `${Math.round((selected.trust_score ?? 1) * 100)}%`,
                    backgroundColor: ringColor(selected),
                  }}
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 px-4 py-2 border-t border-gray-800 bg-gray-950/40 text-xs">
        {[
          { color: '#6366f1', label: 'Planner' },
          { color: '#10b981', label: 'Executor' },
          { color: '#f59e0b', label: 'Validator' },
          { color: '#ef4444', label: 'Sentinel' },
        ].map(({ color, label }) => (
          <span key={label} className="flex items-center gap-1.5 text-gray-500">
            <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ backgroundColor: color }} />
            {label}
          </span>
        ))}
        <span className="ml-auto text-gray-600">{nodes.length} nodes · {links.length} edges</span>
      </div>
    </div>
  );
};
