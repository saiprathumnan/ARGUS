'use client';
import { useSearchParams } from 'next/navigation';
import { useEffect, useMemo, useRef, useState } from 'react';
import { usePersisted, useReducedMotion } from '@/lib/api';
import { useCase } from '@/lib/case';
import { DEFAULT_VIEW, indexGraph, NODE_TYPES, nodeHex, ViewState, visibleNodes } from '@/lib/graph';
import { GraphView } from '@/components/GraphView';
import { EntityInspector } from '@/components/Inspector';
import { Chip, Empty, ErrorState, Icon, Loading, Panel, Segmented } from '@/components/ui/kit';
import { SEV_ORDER, TYPE_LABEL, utc } from '@/lib/format';
import type { Severity } from '@/lib/types';

const GLYPH: Record<string, string> = { evidence: '◆', ip: '●', domain: '⬡', url: '▲', email: '▬', sha256: '⬟', user: '▾', host: '⬢' };

export default function Universe({ params }: { params: { id: string } }) {
  const id = params.id;
  const sp = useSearchParams();
  const reduced = useReducedMotion();
  const { inv, graph, findings } = useCase(id);
  const [saved, setSaved] = usePersisted<Omit<ViewState, 'timeCutoff'>>(`argus.${id}.universe`, { types: DEFAULT_VIEW.types, minSeverity: 'info', isolate: null, expanded: [], temporalDepth: false });
  const [mode, setMode] = usePersisted<'3d' | '2d'>('argus.graphMode', '3d');
  const [selected, setSelected] = usePersisted<string | null>(`argus.${id}.selected`, null);
  const [t, setT] = useState(1000); // time scrubber position, 0..1000 (1000 = everything)
  const [playing, setPlaying] = useState(false);
  const [nonce, setNonce] = useState(0);
  const ix = useMemo(() => (graph ? indexGraph(graph) : null), [graph]);
  const range = useMemo(() => (graph?.time_range.start && graph.time_range.end ? [Date.parse(graph.time_range.start), Date.parse(graph.time_range.end)] as const : null), [graph]);
  const cutoff = range && t < 1000 ? range[0] + ((range[1] - range[0]) * t) / 1000 : null;
  const view: ViewState = useMemo(() => ({ ...saved, timeCutoff: cutoff }), [saved, cutoff]);
  const focus = sp.get('focus');
  const applied = useRef<string | null>(null);

  useEffect(() => { if (focus && ix?.byId.has(focus) && applied.current !== focus) { applied.current = focus; setSelected(focus); setSaved((s) => ({ ...s, isolate: null, types: [...NODE_TYPES], minSeverity: 'info' })); } }, [focus, ix, setSelected, setSaved]);
  useEffect(() => {
    if (!playing) return;
    const step = reduced ? 50 : 4;
    const h = setInterval(() => setT((v) => { if (v >= 1000) { setPlaying(false); return 1000; } return Math.min(1000, v + step); }), reduced ? 600 : 48);
    return () => clearInterval(h);
  }, [playing, reduced]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !(e.target as HTMLElement).closest('input,textarea,select')) { setSelected(null); setSaved((s) => ({ ...s, isolate: null })); } };
    window.addEventListener('keydown', onKey); return () => window.removeEventListener('keydown', onKey);
  }, [setSelected, setSaved]);

  if (inv.loading && !inv.data) return <Loading label="Opening case" />;
  if (inv.error && !inv.data) return <ErrorState error={inv.error} retry={inv.reload} />;
  if (!graph || !ix) return <Loading label="Loading evidence graph" />;
  const node = selected ? ix.byId.get(selected) : null;
  const visCount = visibleNodes(graph, ix, view).size;
  const toggleType = (ty: string) => setSaved((s) => ({ ...s, types: s.types.includes(ty) ? s.types.filter((x) => x !== ty) : [...s.types, ty] }));
  const collapsed = graph.nodes.length > 60 ? [...ix.leafOf.keys()].filter((k) => !saved.expanded.includes(ix.leafOf.get(k)!)).length : 0;

  return (
    <div className="flex h-full min-h-[640px] flex-col gap-3 p-3">
      <div className="panel flex flex-wrap items-center gap-x-4 gap-y-2 px-3 py-2">
        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by entity type">
          {NODE_TYPES.filter((ty) => graph.counts.by_type[ty]).map((ty) => (<Chip key={ty} active={saved.types.includes(ty)} onClick={() => toggleType(ty)}><span aria-hidden="true">{GLYPH[ty]}</span>{TYPE_LABEL[ty]} {graph.counts.by_type[ty]}</Chip>))}
        </div>
        <label className="micro flex items-center gap-2">Min severity
          <select className="field h-7 w-auto py-0 font-mono text-micro uppercase" value={saved.minSeverity} onChange={(e) => setSaved((s) => ({ ...s, minSeverity: e.target.value as Severity }))}>{SEV_ORDER.map((s) => <option key={s} value={s}>{s === 'info' ? 'all' : `${s}+`}</option>)}</select>
        </label>
        <button className="btn h-7" aria-pressed={saved.temporalDepth} onClick={() => { setSaved((s) => ({ ...s, temporalDepth: !s.temporalDepth })); setNonce((n) => n + 1); }} title="Place entities along the depth axis by when they were first observed" disabled={mode === '2d' || !range}>
          <Icon name="timeline" size={13} />Temporal depth {saved.temporalDepth ? 'on' : 'off'}
        </button>
        {collapsed > 0 && <button className="btn h-7" onClick={() => setSaved((s) => ({ ...s, expanded: graph.nodes.filter((n) => n.type === 'evidence').map((n) => n.id) }))}><Icon name="layers" size={13} />Expand {collapsed} clustered</button>}
        {saved.expanded.length > 0 && graph.nodes.length > 60 && <button className="btn h-7" onClick={() => setSaved((s) => ({ ...s, expanded: [] }))}>Collapse clusters</button>}
        {saved.isolate && <button className="btn h-7 border-amber text-amber" onClick={() => setSaved((s) => ({ ...s, isolate: null }))}><Icon name="close" size={13} />Exit isolation</button>}
        <div className="ml-auto flex items-center gap-2">
          <span className="micro">{visCount} / {graph.counts.nodes} entities</span>
          <button className="btn h-7" onClick={() => { setSelected(null); setNonce((n) => n + 1); }} title="Frame all visible entities"><Icon name="focus" size={13} />Frame</button>
          <Segmented label="Graph renderer" value={mode} onChange={setMode} options={[{ id: '3d', label: '3D' }, { id: '2d', label: '2D' }]} />
        </div>
      </div>

      <div className="grid grid-cols-[minmax(0,1fr)] min-h-0 flex-1 gap-3 lg:grid-cols-[minmax(0,1fr)_380px]">
        <div className="panel relative flex min-h-[420px] flex-col">
          <div className="relative min-h-0 flex-1">
            <GraphView graph={graph} view={view} mode={mode} selected={selected} onSelect={setSelected} focusNonce={nonce}
              onExpand={(eid) => setSaved((s) => ({ ...s, expanded: s.expanded.includes(eid) ? s.expanded.filter((x) => x !== eid) : [...s.expanded, eid] }))} />
            <div className="pointer-events-none absolute left-3 top-3 space-y-1">
              <div className="micro">Legend</div>
              {[['#E84B55', 'high / critical'], ['#FF9D35', 'medium'], ['#52D9E8', 'low'], ['#B9C2CE', 'no suspicious finding']].map(([c, l]) => (<div key={l} className="flex items-center gap-1.5"><span className="h-1.5 w-1.5" style={{ background: c }} /><span className="micro normal-case tracking-normal">{l}</span></div>))}
              <div className="flex items-center gap-1.5 pt-1"><span className="h-px w-4 bg-titanium" /><span className="micro normal-case tracking-normal">observed / derived</span></div>
              <div className="flex items-center gap-1.5"><span className="h-px w-4 border-t border-dashed border-titanium" /><span className="micro normal-case tracking-normal">inferred</span></div>
            </div>
            {mode === '3d' && <div className="micro pointer-events-none absolute bottom-2 right-2 bg-obsidian/70 px-1.5 py-0.5 normal-case tracking-normal">drag rotate · right-drag pan · scroll zoom · click select · double-click evidence to expand · esc clear</div>}
          </div>
          {/* time dimension */}
          <div className="flex items-center gap-3 border-t border-line px-3 py-2">
            <button className="btn h-7 w-7 px-0" disabled={!range} aria-label={playing ? 'Pause time playback' : 'Play entities in order of first observation'} onClick={() => { if (!playing && t >= 1000) setT(0); setPlaying((p) => !p); }}><Icon name={playing ? 'pause' : 'play'} size={13} /></button>
            <span className="micro shrink-0 normal-case tracking-normal">{range ? utc(new Date(range[0]).toISOString()) : 'no dated entities'}</span>
            <input type="range" min={0} max={1000} value={t} disabled={!range} onChange={(e) => { setPlaying(false); setT(Number(e.target.value)); }} className="h-1 min-w-0 flex-1 accent-[#FF9D35]" aria-label="Show entities first observed up to this time" aria-valuetext={cutoff ? utc(new Date(cutoff).toISOString()) : 'all time'} />
            <span className="micro shrink-0 normal-case tracking-normal">{range ? utc(new Date(range[1]).toISOString()) : ''}</span>
            <span className={`data w-[150px] shrink-0 text-right ${cutoff ? 'text-amber' : 'text-titanium-mute'}`}>{cutoff ? `≤ ${utc(new Date(cutoff).toISOString())}` : 'all time'}</span>
          </div>
        </div>

        <Panel title="Evidence inspector" className="min-h-[320px]">
          {node ? (
            <EntityInspector node={node} graph={graph} ix={ix} findings={findings} caseId={id} onSelect={(nid) => { setSelected(nid); if (saved.isolate) setSaved((s) => ({ ...s, isolate: nid })); }}
              isolated={saved.isolate === node.id} onIsolate={() => setSaved((s) => ({ ...s, isolate: s.isolate === node.id ? null : node.id }))}
              expanded={saved.expanded.includes(node.id)} onExpand={() => setSaved((s) => ({ ...s, expanded: s.expanded.includes(node.id) ? s.expanded.filter((x) => x !== node.id) : [...s.expanded, node.id] }))} />
          ) : (
            <div className="flex h-full flex-col">
              <Empty icon="universe" title="Select an entity">Click any node to see where it was found, what it connects to, and the evidence behind each connection.</Empty>
              <div className="border-t border-line p-3">
                <div className="micro mb-2">Highest-severity entities</div>
                <ul>{graph.nodes.filter((n) => n.type !== 'evidence' && n.severity !== 'info').sort((a, b) => SEV_ORDER.indexOf(b.severity) - SEV_ORDER.indexOf(a.severity) || b.sources - a.sources).slice(0, 8).map((n) => (
                  <li key={n.id}><button className="flex w-full items-center gap-2 py-1 text-left hover:text-paper" onClick={() => setSelected(n.id)}><span style={{ color: nodeHex(n) }} aria-hidden="true">{GLYPH[n.type]}</span><span className="data min-w-0 flex-1 truncate">{n.label}</span><span className="micro">{n.severity}</span></button></li>))}
                  {!graph.nodes.some((n) => n.type !== 'evidence' && n.severity !== 'info') && <li className="text-data text-titanium-mute">No entity is tied to a suspicious finding.</li>}
                </ul>
              </div>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
