'use client';
import { useMemo } from 'react';
import ReactFlow, { Background, Controls, Edge, Handle, MiniMap, Node, NodeProps, Position } from 'reactflow';
import 'reactflow/dist/style.css';
import type { UniverseProps } from './EvidenceUniverse';
import { nodeHex } from '@/lib/graph';
import { short, TYPE_LABEL } from '@/lib/format';

const GLYPH: Record<string, string> = { evidence: '◆', ip: '●', domain: '⬡', url: '▲', email: '▬', sha256: '⬟', user: '▾', host: '⬢' };

function EntityNode({ data, selected }: NodeProps) {
  return (
    <div className={`flex items-center gap-1.5 border bg-graphite px-2 py-1 ${selected ? 'border-amber' : 'border-line-strong'}`} style={{ opacity: data.dim ? 0.35 : 1 }} title={`${TYPE_LABEL[data.type] || data.type}: ${data.full}`}>
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} isConnectable={false} />
      <span style={{ color: data.hex }} aria-hidden="true">{GLYPH[data.type] || '●'}</span>
      <span className="font-mono text-[10px] text-titanium">{data.label}</span>
      {data.extra ? <span className="font-mono text-[10px] text-titanium-mute">+{data.extra}</span> : null}
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} isConnectable={false} />
    </div>
  );
}
const nodeTypes = { entity: EntityNode };

/** 2D alternative to the Evidence Universe: same data, same filters, same selection. Used when WebGL is unavailable or by choice. */
export default function Graph2D(p: UniverseProps) {
  const neighbours = useMemo(() => new Set((p.selected ? p.ix.adj.get(p.selected) || [] : []).map((l) => l.other)), [p.selected, p.ix]);
  const nodes: Node[] = useMemo(() => p.graph.nodes.filter((n) => p.visible.has(n.id)).map((n) => {
    const [x, y] = p.positions.get(n.id) || [0, 0];
    return { id: n.id, type: 'entity', position: { x: x * 52, y: -y * 40 }, selected: n.id === p.selected, draggable: true,
      data: { type: n.type, label: short(n.label, 28), full: n.value, hex: nodeHex(n), dim: !!p.selected && n.id !== p.selected && !neighbours.has(n.id), extra: n.type === 'evidence' && p.graph.nodes.length > 60 ? p.ix.clusterSize.get(n.id) : 0 } };
  }), [p.graph, p.visible, p.positions, p.selected, p.ix, neighbours]);
  const edges: Edge[] = useMemo(() => p.graph.edges.filter((e) => p.visible.has(e.source) && p.visible.has(e.target)).map((e) => {
    const hot = p.selected && (e.source === p.selected || e.target === p.selected);
    return { id: e.id, source: e.source, target: e.target, label: hot ? e.relation.replace(/_/g, ' ') : undefined,
      labelStyle: { fill: '#FF9D35', fontSize: 9, fontFamily: 'IBM Plex Mono' }, labelBgStyle: { fill: '#080A0E' },
      style: { stroke: hot ? '#FF9D35' : `rgba(185,194,206,${e.relation === 'contains' ? 0.14 : e.basis === 'observed' ? 0.42 : 0.26})`, strokeWidth: hot ? 1.4 : 1, strokeDasharray: e.basis === 'inferred' ? '4 3' : undefined } };
  }), [p.graph, p.visible, p.selected]);
  return (
    <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.08 }} minZoom={0.1} maxZoom={2.5} nodesConnectable={false} proOptions={{ hideAttribution: true }}
      onNodeClick={(_, n) => p.onSelect(n.id)} onPaneClick={() => p.onSelect(null)} onNodeDoubleClick={(_, n) => n.data.type === 'evidence' && p.onExpand?.(n.id)} aria-label="Two-dimensional evidence graph">
      <Background color="rgba(185,194,206,0.08)" gap={48} />
      <Controls showInteractive={false} />
      {!p.compact && <MiniMap pannable zoomable nodeColor={(n) => n.data.hex} maskColor="rgba(8,10,14,0.7)" style={{ background: '#151A22', width: 150, height: 104 }} />}
    </ReactFlow>
  );
}
