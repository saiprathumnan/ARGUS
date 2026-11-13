import type { Graph, GraphEdge, GraphNode, Severity } from './types';
import { SEV_ORDER } from './format';

export const NODE_TYPES = ['evidence', 'ip', 'domain', 'url', 'email', 'sha256', 'user', 'host'] as const;
export const TYPE_HEX: Record<string, string> = { evidence: '#EEF1F4', ip: '#B9C2CE', domain: '#B9C2CE', url: '#B9C2CE', email: '#B9C2CE', sha256: '#B9C2CE', user: '#B9C2CE', host: '#B9C2CE' };

export interface ViewState { types: string[]; minSeverity: Severity; isolate: string | null; expanded: string[]; timeCutoff: number | null; temporalDepth: boolean }
export const DEFAULT_VIEW: ViewState = { types: [...NODE_TYPES], minSeverity: 'info', isolate: null, expanded: [], timeCutoff: null, temporalDepth: false };

export interface Indexed { byId: Map<string, GraphNode>; adj: Map<string, { edge: GraphEdge; other: string }[]>; leafOf: Map<string, string>; clusterSize: Map<string, number> }

/** Adjacency + "cluster" detection: an info-level indicator attached to exactly one evidence item and nothing else is a leaf of that evidence. */
export function indexGraph(g: Graph): Indexed {
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const adj = new Map<string, { edge: GraphEdge; other: string }[]>();
  for (const n of g.nodes) adj.set(n.id, []);
  for (const e of g.edges) {
    adj.get(e.source)?.push({ edge: e, other: e.target });
    adj.get(e.target)?.push({ edge: e, other: e.source });
  }
  const leafOf = new Map<string, string>();
  const clusterSize = new Map<string, number>();
  for (const n of g.nodes) {
    if (n.type === 'evidence' || n.severity !== 'info') continue;
    const links = adj.get(n.id) || [];
    if (links.length === 1 && links[0].edge.relation === 'contains' && byId.get(links[0].other)?.type === 'evidence') {
      leafOf.set(n.id, links[0].other);
      clusterSize.set(links[0].other, (clusterSize.get(links[0].other) || 0) + 1);
    }
  }
  return { byId, adj, leafOf, clusterSize };
}

/** Which nodes are drawn, given filters. Collapsing only applies to larger graphs. Nothing is ever invented: this only hides. */
export function visibleNodes(g: Graph, ix: Indexed, v: ViewState): Set<string> {
  const minRank = SEV_ORDER.indexOf(v.minSeverity);
  const collapse = g.nodes.length > 60;
  const out = new Set<string>();
  let scope: Set<string> | null = null;
  if (v.isolate && ix.byId.has(v.isolate)) {
    scope = new Set([v.isolate]);
    for (const l of ix.adj.get(v.isolate) || []) scope.add(l.other);
  }
  for (const n of g.nodes) {
    if (scope && !scope.has(n.id)) continue;
    if (!v.types.includes(n.type)) continue;
    if (n.type !== 'evidence' && SEV_ORDER.indexOf(n.severity) < minRank) continue;
    if (v.timeCutoff != null && n.type !== 'evidence' && n.first_seen && Date.parse(n.first_seen) > v.timeCutoff) continue;
    const parent = ix.leafOf.get(n.id);
    if (collapse && parent && !scope && !v.expanded.includes(parent)) continue;
    out.add(n.id);
  }
  return out;
}

function hash(s: string): number { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0) / 4294967295; }

/** Deterministic 3D force layout (repulsion + springs + centring). Runs once per graph. */
export function layout3d(g: Graph): Map<string, [number, number, number]> {
  const n = g.nodes.length;
  const pos = new Float32Array(n * 3);
  const idx = new Map<string, number>();
  g.nodes.forEach((node, i) => {
    idx.set(node.id, i);
    const a = hash(node.id) * Math.PI * 2, b = Math.acos(2 * hash(node.id + '#') - 1), r = 6 + 6 * hash(node.id + '!');
    pos[i * 3] = r * Math.sin(b) * Math.cos(a); pos[i * 3 + 1] = r * Math.sin(b) * Math.sin(a); pos[i * 3 + 2] = r * Math.cos(b);
  });
  const links = g.edges.map((e) => [idx.get(e.source)!, idx.get(e.target)!, e.relation === 'contains' ? 3.2 : 4.2] as const).filter(([a, b]) => a !== undefined && b !== undefined);
  const iters = n <= 150 ? 260 : n <= 400 ? 140 : 70;
  const disp = new Float32Array(n * 3);
  for (let it = 0; it < iters; it++) {
    disp.fill(0);
    const temp = 0.9 * (1 - it / iters) + 0.02;
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let dx = pos[i * 3] - pos[j * 3], dy = pos[i * 3 + 1] - pos[j * 3 + 1], dz = pos[i * 3 + 2] - pos[j * 3 + 2];
        let d2 = dx * dx + dy * dy + dz * dz;
        if (d2 < 0.01) { dx = 0.1; dy = 0.1; dz = 0.1; d2 = 0.03; }
        if (d2 > 400) continue;
        const f = 9 / d2, d = Math.sqrt(d2);
        dx = (dx / d) * f; dy = (dy / d) * f; dz = (dz / d) * f;
        disp[i * 3] += dx; disp[i * 3 + 1] += dy; disp[i * 3 + 2] += dz;
        disp[j * 3] -= dx; disp[j * 3 + 1] -= dy; disp[j * 3 + 2] -= dz;
      }
    }
    for (const [a, b, rest] of links) {
      const dx = pos[b * 3] - pos[a * 3], dy = pos[b * 3 + 1] - pos[a * 3 + 1], dz = pos[b * 3 + 2] - pos[a * 3 + 2];
      const d = Math.sqrt(dx * dx + dy * dy + dz * dz) || 0.01;
      const f = (d - rest) * 0.12;
      disp[a * 3] += (dx / d) * f; disp[a * 3 + 1] += (dy / d) * f; disp[a * 3 + 2] += (dz / d) * f;
      disp[b * 3] -= (dx / d) * f; disp[b * 3 + 1] -= (dy / d) * f; disp[b * 3 + 2] -= (dz / d) * f;
    }
    for (let i = 0; i < n; i++) {
      for (let k = 0; k < 3; k++) {
        const c = i * 3 + k;
        disp[c] -= pos[c] * 0.012;
        pos[c] += Math.max(-1.2, Math.min(1.2, disp[c])) * temp;
      }
    }
  }
  const out = new Map<string, [number, number, number]>();
  g.nodes.forEach((node, i) => out.set(node.id, [pos[i * 3], pos[i * 3 + 1], pos[i * 3 + 2]]));
  return out;
}

export function nodeHex(n: GraphNode): string {
  if (n.severity === 'high' || n.severity === 'critical') return '#E84B55';
  if (n.severity === 'medium') return '#FF9D35';
  if (n.severity === 'low') return '#52D9E8';
  return n.type === 'evidence' ? '#EEF1F4' : n.internal ? '#7C8796' : '#B9C2CE';
}
