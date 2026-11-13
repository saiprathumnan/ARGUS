'use client';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useApi, usePersisted, useReducedMotion, webglAvailable } from '@/lib/api';
import type { InvDetail, Timeline, TimelineEntry } from '@/lib/types';
import { Chip, Empty, ErrorState, Icon, KV, Loading, Panel, Segmented, SeverityTag, Tag } from '@/components/ui/kit';
import { SEV_HEX, short, utc, words } from '@/lib/format';

const Scene3D = dynamic(() => import('@/components/three/TemporalScene'), { ssr: false, loading: () => <Loading label="Loading 3D timeline" /> });
const BASIS: Record<string, { label: string; tone: 'cyan' | 'amber' | 'default' }> = { confirmed: { label: 'confirmed', tone: 'cyan' }, inferred: { label: 'inferred', tone: 'amber' }, submission_time: { label: 'submission time', tone: 'default' } };

/** 2D alternative: swimlanes per event category. Same data, selection and playhead as the 3D scene. */
function Swimlanes({ tl, playhead, selected, onSelect, highlight }: { tl: Timeline; playhead: number; selected: string | null; onSelect: (id: string | null) => void; highlight: Set<string> }) {
  const t0 = Date.parse(tl.range!.start), span = Math.max(1, Date.parse(tl.range!.end) - t0);
  const W = 1000, laneH = 46, padL = 96, H = tl.layers.length * laneH + 34;
  const x = (iso: string) => padL + ((W - padL - 16) * (Date.parse(iso) - t0)) / span;
  return (
    <div className="h-full overflow-auto p-3">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full min-w-[720px]" role="img" aria-label="Incident timeline swimlanes" onClick={() => onSelect(null)}>
        {tl.layers.map((l, i) => (<g key={l}><rect x={padL} y={i * laneH + 4} width={W - padL - 16} height={laneH - 8} fill="#1D242E" opacity="0.55" /><text x={8} y={i * laneH + laneH / 2 + 3} fill="#B9C2CE" fontSize="10" fontFamily="IBM Plex Mono" letterSpacing="1.4">{l.toUpperCase()}</text></g>))}
        {Array.from({ length: 7 }, (_, i) => { const px = padL + ((W - padL - 16) * i) / 6; return (<g key={i}><line x1={px} y1={0} x2={px} y2={H - 30} stroke="#B9C2CE" strokeOpacity="0.12" /><text x={px} y={H - 14} fill="#7C8796" fontSize="9" fontFamily="IBM Plex Mono" textAnchor="middle">{new Date(t0 + (span * i) / 6).toISOString().slice(11, 19)}</text><text x={px} y={H - 3} fill="#4A5360" fontSize="8" fontFamily="IBM Plex Mono" textAnchor="middle">{new Date(t0 + (span * i) / 6).toISOString().slice(0, 10)}</text></g>); })}
        {tl.entries.map((e) => {
          const li = tl.layers.indexOf(e.layer), h = e.severity === 'info' ? 8 : e.severity === 'low' ? 14 : e.severity === 'medium' ? 22 : 30;
          const past = (Date.parse(e.at) - t0) / span <= playhead, sel = e.id === selected, hl = highlight.has(e.id);
          const col = sel ? '#FF9D35' : hl ? '#52D9E8' : SEV_HEX[e.severity];
          return (<rect key={e.id} x={x(e.at) - (sel ? 3 : 1.5)} y={li * laneH + laneH - 6 - h} width={sel ? 6 : 3} height={h} fill={e.time_basis === 'confirmed' ? col : 'none'} stroke={col} strokeWidth={e.time_basis === 'confirmed' ? 0 : 1}
            opacity={past ? (selected && !sel && !hl ? 0.45 : 1) : 0.18} className="cursor-pointer" onClick={(ev) => { ev.stopPropagation(); onSelect(e.id); }}><title>{`${utc(e.at)} · ${e.summary}`}</title></rect>);
        })}
        <line x1={padL + (W - padL - 16) * playhead} y1={0} x2={padL + (W - padL - 16) * playhead} y2={H - 30} stroke="#FF9D35" strokeWidth="1.2" />
      </svg>
    </div>
  );
}

export default function Temporal({ params }: { params: { id: string } }) {
  const id = params.id;
  const reduced = useReducedMotion();
  const inv = useApi<InvDetail>(`/investigations/${id}`, 4000);
  const tl = useApi<Timeline>(`/investigations/${id}/timeline${inv.data ? `?s=${inv.data.status}${inv.data.counts.events}` : ''}`);
  const [mode, setMode] = usePersisted<'3d' | '2d'>('argus.timelineMode', '3d');
  const [gl, setGl] = useState(true);
  const [playhead, setPlayhead] = useState(1);
  const [playing, setPlaying] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [entity, setEntity] = useState<string | null>(null);
  const [layers, setLayers] = useState<string[] | null>(null);
  const listRef = useRef<HTMLOListElement>(null);
  useEffect(() => { setGl(webglAvailable()); }, []);
  useEffect(() => {
    if (!playing) return;
    const h = setInterval(() => setPlayhead((p) => { if (p >= 1) { setPlaying(false); return 1; } return Math.min(1, p + (reduced ? 0.05 : 0.004)); }), reduced ? 500 : 50);
    return () => clearInterval(h);
  }, [playing, reduced]);

  const data = useMemo(() => {
    if (!tl.data) return null;
    const act = layers ?? tl.data.layers;
    return { ...tl.data, layers: tl.data.layers.filter((l) => act.includes(l)), entries: tl.data.entries.filter((e) => act.includes(e.layer)) };
  }, [tl.data, layers]);
  const sel = data?.entries.find((e) => e.id === selected) || null;
  const highlight = useMemo(() => {
    const out = new Set<string>(); if (!data) return out;
    const ents = entity ? [entity] : sel ? sel.entities : [];
    if (ents.length) for (const e of data.entries) if (e.id !== selected && e.entities.some((x) => ents.includes(x))) out.add(e.id);
    return out;
  }, [data, entity, sel, selected]);
  useEffect(() => { if (selected) listRef.current?.querySelector(`[data-id="${selected}"]`)?.scrollIntoView({ block: 'nearest' }); }, [selected]);

  if (inv.loading && !inv.data) return <Loading label="Opening case" />;
  if (inv.error && !inv.data) return <ErrorState error={inv.error} retry={inv.reload} />;
  if (tl.loading && !tl.data) return <Loading label="Reconstructing timeline" />;
  if (tl.error) return <ErrorState error={tl.error} retry={tl.reload} />;
  if (!data || !tl.data?.range) return <div className="p-3"><Panel title="Temporal reconstruction"><Empty icon="timeline" title="No dated events">{inv.data?.status === 'created' ? 'Start the analysis to extract events from the evidence.' : 'None of the submitted evidence produced an event with a usable timestamp, so there is nothing to place on a timeline.'}</Empty></Panel></div>;

  const t0 = Date.parse(tl.data.range.start), span = Math.max(1, Date.parse(tl.data.range.end) - t0);
  const cutoffIso = new Date(t0 + span * playhead).toISOString();
  const counts = { confirmed: data.entries.filter((e) => e.time_basis === 'confirmed').length, inferred: data.entries.filter((e) => e.time_basis === 'inferred').length, submission: data.entries.filter((e) => e.time_basis === 'submission_time').length };
  const seq = tl.data.attack_sequence;
  const findEntry = (fid: string) => data.entries.find((e) => e.finding_ids.includes(fid));

  return (
    <div className="flex h-full min-h-[680px] flex-col gap-3 p-3">
      <div className="panel flex flex-wrap items-center gap-x-4 gap-y-2 px-3 py-2">
        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Event layers">{tl.data.layers.map((l) => (<Chip key={l} active={(layers ?? tl.data!.layers).includes(l)} onClick={() => setLayers((p) => { const cur = p ?? tl.data!.layers; return cur.includes(l) ? cur.filter((x) => x !== l) : [...cur, l]; })}>{l} {tl.data!.entries.filter((e) => e.layer === l).length}</Chip>))}</div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5"><span className="h-2.5 w-1 bg-titanium" /><span className="micro normal-case tracking-normal">confirmed {counts.confirmed}</span></span>
          <span className="flex items-center gap-1.5"><span className="h-2.5 w-1 border border-amber" /><span className="micro normal-case tracking-normal text-amber">inferred {counts.inferred}</span></span>
          {counts.submission > 0 && <span className="flex items-center gap-1.5"><span className="h-2.5 w-1 border border-titanium-mute" /><span className="micro normal-case tracking-normal">submission time {counts.submission}</span></span>}
        </div>
        {entity && <button className="btn h-7 border-cyan text-cyan" onClick={() => setEntity(null)}><Icon name="close" size={13} />{short(entity, 30)}</button>}
        <div className="ml-auto flex items-center gap-2"><span className="micro">{data.entries.length} of {tl.data.total_events} events</span><Segmented label="Timeline renderer" value={mode} onChange={setMode} options={[{ id: '3d', label: '3D' }, { id: '2d', label: '2D' }]} /></div>
      </div>

      <div className="grid grid-cols-[minmax(0,1fr)] min-h-0 flex-1 gap-3 xl:grid-rows-[minmax(340px,54%)_minmax(0,1fr)]">
        <div className="panel flex min-h-[320px] flex-col">
          <div className="relative min-h-0 flex-1">
            {mode === '3d' && gl ? <Scene3D timeline={data} playhead={playhead} selected={selected} onSelect={setSelected} highlight={highlight} reducedMotion={reduced} /> : <Swimlanes tl={data} playhead={playhead} selected={selected} onSelect={setSelected} highlight={highlight} />}
            {mode === '3d' && !gl && <div className="micro absolute left-3 top-3 border border-line bg-obsidian/80 px-2 py-1 normal-case tracking-normal">WebGL is unavailable, so the 2D timeline is shown.</div>}
          </div>
          <div className="flex items-center gap-3 border-t border-line px-3 py-2">
            <button className="btn h-7 w-7 px-0" aria-label={playing ? 'Pause' : 'Play timeline'} onClick={() => { if (!playing && playhead >= 1) setPlayhead(0); setPlaying((p) => !p); }}><Icon name={playing ? 'pause' : 'play'} size={13} /></button>
            <span className="micro shrink-0 normal-case tracking-normal">{utc(tl.data.range.start)}</span>
            <input type="range" min={0} max={1000} value={Math.round(playhead * 1000)} onChange={(e) => { setPlaying(false); setPlayhead(Number(e.target.value) / 1000); }} className="h-1 min-w-0 flex-1 accent-[#FF9D35]" aria-label="Timeline position" aria-valuetext={utc(cutoffIso)} />
            <span className="micro shrink-0 normal-case tracking-normal">{utc(tl.data.range.end)}</span>
            <span className="data w-[150px] shrink-0 text-right text-amber">{utc(cutoffIso)}</span>
          </div>
        </div>

        <div className="grid grid-cols-[minmax(0,1fr)] min-h-0 gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          {sel ? (
            <Panel title="Event" actions={<button className="btn-ghost h-6 px-1" onClick={() => setSelected(null)} aria-label="Close event"><Icon name="close" size={13} /></button>} className="min-h-[220px] lg:order-2" bodyClass="overflow-auto">
              <div className="p-3">
                <div className="flex flex-wrap items-center gap-2"><Tag>{sel.layer}</Tag><SeverityTag severity={sel.severity} /><Tag tone={BASIS[sel.time_basis].tone}>{BASIS[sel.time_basis].label}</Tag></div>
                <p className="mt-2 text-body text-paper">{sel.summary}</p>
                <dl className="mt-2">
                  <KV k="Time (UTC)">{utc(sel.at)}</KV><KV k="Time basis" mono={false}>{sel.time_basis_label}</KV>
                  <KV k="Evidence"><Link className="text-cyan hover:underline" href={`/i/${id}/evidence?e=${sel.evidence_id}`}>{sel.evidence_id}</Link> · {sel.record_ref}</KV>
                  {sel.entities.length > 0 && <KV k="Entities" mono={false}><div className="flex flex-wrap gap-1">{sel.entities.map((e) => (<button key={e} onClick={() => setEntity(entity === e ? null : e)} aria-pressed={entity === e} className={`border px-1.5 font-mono text-[11px] ${entity === e ? 'border-cyan text-cyan' : 'border-line-strong text-titanium hover:text-paper'}`}>{short(e, 34)}</button>))}</div><div className="micro mt-1 normal-case tracking-normal">Select an entity to highlight every event that involves it ({highlight.size} highlighted).</div></KV>}
                  {sel.finding_ids.length > 0 && <KV k="Findings">{sel.finding_ids.map((f) => <Link key={f} className="mr-2 text-cyan hover:underline" href={`/i/${id}?f=${f}`}>{f}</Link>)}</KV>}
                </dl>
              </div>
            </Panel>
          ) : seq ? (
            <Panel title="Attack sequence" meta={<span className="text-amber">inferred</span>} className="min-h-[220px] lg:order-2" bodyClass="overflow-auto">
              <p className="border-b border-line px-3 py-2 text-data text-titanium-mute">{seq.basis}</p>
              <ol>{seq.steps.map((s, i) => { const e = findEntry(s.finding_id); return (
                <li key={`${s.finding_id}${i}`} className="border-b border-line last:border-0"><button className="grid w-full grid-cols-[22px_1fr] gap-2 px-3 py-1.5 text-left hover:bg-elevated disabled:hover:bg-transparent" disabled={!e} onClick={() => e && setSelected(e.id)}>
                  <span className="data text-amber">{String(i + 1).padStart(2, '0')}</span><span><span className="micro">{words(s.phase)} · {s.at ? utc(s.at) : 'untimed'}</span><span className="block text-data text-titanium">{s.title}</span></span></button></li>); })}</ol>
            </Panel>
          ) : (
            <Panel title="Event" className="min-h-[220px] lg:order-2"><Empty icon="timeline" title="Select an event">Click a block in the scene or a line in the chronology to see its evidence reference, time basis and related entities.</Empty></Panel>
          )}
          <Panel title="Chronology" meta={`≤ ${utc(cutoffIso, false)}`} className="min-h-[220px] lg:order-1" bodyClass="overflow-auto">
            <ol ref={listRef}>{data.entries.map((e) => { const past = Date.parse(e.at) <= t0 + span * playhead; return (
              <li key={e.id} data-id={e.id} className={`border-b border-line ${past ? '' : 'opacity-35'}`}>
                <button onClick={() => setSelected(e.id)} className={`grid w-full grid-cols-[62px_1fr] gap-2 px-3 py-1.5 text-left hover:bg-elevated ${selected === e.id ? 'bg-elevated' : ''}`} aria-current={selected === e.id}>
                  <time className="micro pt-0.5 normal-case tracking-normal" dateTime={e.at}>{utc(e.at, false)}</time>
                  <span className="min-w-0"><span className="flex items-center gap-2"><span className="h-1.5 w-1.5 shrink-0" style={{ background: e.time_basis === 'confirmed' ? SEV_HEX[e.severity] : 'transparent', outline: e.time_basis === 'confirmed' ? 'none' : `1px solid ${SEV_HEX[e.severity]}` }} /><span className="micro">{e.layer}</span>{e.time_basis !== 'confirmed' && <span className="micro text-amber">{BASIS[e.time_basis].label}</span>}{highlight.has(e.id) && <span className="micro text-cyan">related</span>}</span>
                    <span className="block truncate text-data text-titanium">{e.summary}</span></span>
                </button></li>); })}</ol>
          </Panel>
        </div>
      </div>
      {!!tl.data.omitted_submission_events && <p className="micro shrink-0 normal-case tracking-normal">{tl.data.omitted_submission_events} submission event(s) are left off the axis: they record when evidence was handed to ARGUS, not when something happened.</p>}
      {tl.data.inconsistencies.length > 0 && (
        <Panel title="Timeline caveats" meta={`${tl.data.inconsistencies.length}`} className="shrink-0"><ul className="p-3">{tl.data.inconsistencies.map((i, k) => (<li key={k} className="flex gap-2 py-0.5 text-data text-titanium"><Icon name="alert" size={13} className="mt-[3px] shrink-0 text-amber" /><span><span className="data text-titanium-mute">{i.evidence_id}</span> — {i.issue}</span></li>))}</ul></Panel>
      )}
    </div>
  );
}
