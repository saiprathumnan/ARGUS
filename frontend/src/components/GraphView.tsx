'use client';
import dynamic from 'next/dynamic';
import { useEffect, useMemo, useState } from 'react';
import type { Graph } from '@/lib/types';
import { DEFAULT_VIEW, indexGraph, layout3d, ViewState, visibleNodes } from '@/lib/graph';
import { useReducedMotion, webglAvailable } from '@/lib/api';
import { Empty, Loading } from '@/components/ui/kit';

// 3D and 2D renderers are separate lazy chunks: neither is downloaded until a graph is actually shown.
const Universe3D = dynamic(() => import('@/components/three/EvidenceUniverse'), { ssr: false, loading: () => <Loading label="Loading 3D scene" /> });
const Graph2D = dynamic(() => import('@/components/three/Graph2D'), { ssr: false, loading: () => <Loading label="Loading 2D graph" /> });

export function useGraphModel(graph: Graph | null, view: ViewState = DEFAULT_VIEW) {
  const ix = useMemo(() => (graph ? indexGraph(graph) : null), [graph]);
  const positions = useMemo(() => (graph ? layout3d(graph) : new Map()), [graph]);
  const visible = useMemo(() => (graph && ix ? visibleNodes(graph, ix, view) : new Set<string>()), [graph, ix, view]);
  return { ix, positions, visible };
}

export function GraphView({ graph, view, mode, selected, onSelect, onExpand, compact, focusNonce }: {
  graph: Graph; view: ViewState; mode: '3d' | '2d'; selected: string | null; onSelect: (id: string | null) => void; onExpand?: (id: string) => void; compact?: boolean; focusNonce?: number;
}) {
  const reduced = useReducedMotion();
  const [gl, setGl] = useState<boolean | null>(null);
  useEffect(() => { setGl(webglAvailable()); }, []);
  const { ix, positions, visible } = useGraphModel(graph, view);
  if (!ix || gl === null) return <Loading label="Preparing graph" />;
  if (graph.nodes.length === 0) return <Empty icon="universe" title="No entities yet">Entities appear here once evidence has been parsed. Nothing is drawn that was not extracted from evidence.</Empty>;
  if (visible.size === 0) return <Empty icon="universe" title="Every entity is filtered out">Loosen the type, severity or time filters to bring entities back.</Empty>;
  const props = { graph, ix, positions, visible, selected, onSelect, onExpand, temporalDepth: view.temporalDepth, reducedMotion: reduced, compact, focusNonce };
  const use3d = mode === '3d' && gl;
  return (
    <div className="relative h-full w-full">
      {use3d ? <Universe3D {...props} /> : <Graph2D {...props} />}
      {mode === '3d' && !gl && <div className="micro absolute left-3 top-3 border border-line bg-obsidian/80 px-2 py-1 normal-case tracking-normal">WebGL is unavailable on this device, so the 2D graph is shown.</div>}
    </div>
  );
}
