'use client';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { api, ApiError, usePersisted } from '@/lib/api';
import { useCase } from '@/lib/case';
import { DEFAULT_VIEW, indexGraph } from '@/lib/graph';
import { GraphView } from '@/components/GraphView';
import { EntityInspector, FindingCard } from '@/components/Inspector';
import { Empty, ErrorState, Icon, Loading, Panel, Segmented, StatusDot, Tag, VerdictBadge } from '@/components/ui/kit';
import { AGENT_LABEL, bytes, KIND_LABEL, SEV_ORDER, STAGES, utc, words } from '@/lib/format';
import type { Severity } from '@/lib/types';

export default function Workspace({ params }: { params: { id: string } }) {
  const id = params.id;
  const router = useRouter();
  const sp = useSearchParams();
  const { inv, events, graph, findings, running } = useCase(id);
  const [selected, setSelected] = useState<string | null>(null);
  const [mode, setMode] = usePersisted<'3d' | '2d'>('argus.graphMode', '3d');
  const [fFilter, setFFilter] = usePersisted<'key' | 'all' | 'rejected'>(`argus.${id}.findingFilter`, 'key');
  const [actionErr, setActionErr] = useState<string | null>(null);
  const stream = useRef<HTMLDivElement>(null);
  const ix = useMemo(() => (graph ? indexGraph(graph) : null), [graph]);
  const focusFinding = sp.get('f');

  useEffect(() => { if (stream.current) stream.current.scrollTop = stream.current.scrollHeight; }, [events.length]);
  useEffect(() => { if (focusFinding) document.getElementById(focusFinding)?.scrollIntoView({ block: 'center' }); }, [focusFinding, findings.length]);

  if (inv.loading && !inv.data) return <Loading label="Opening case" />;
  if (inv.error && !inv.data) return <ErrorState error={inv.error} retry={inv.reload} />;
  const d = inv.data!;
  const stageIdx = d.status === 'failed' ? -1 : STAGES.findIndex((s) => s.id === d.stage);
  const node = selected && ix ? ix.byId.get(selected) : null;
  const shown = findings.filter((f) => fFilter === 'all' ? f.verification_status !== 'rejected' : fFilter === 'rejected' ? f.verification_status === 'rejected'
    : f.verification_status !== 'rejected' && (f.classification === 'suspicious' || f.classification === 'confirmed_malicious' || f.classification === 'unverified_intel'));
  const sevCount = (s: Severity) => findings.filter((f) => f.severity === s && f.verification_status !== 'rejected' && f.classification !== 'benign').length;

  const act = async (fn: () => Promise<unknown>) => { setActionErr(null); try { await fn(); inv.reload(); } catch (e) { setActionErr((e as ApiError).message); } };

  return (
    <div className="flex min-h-full flex-col gap-3 p-3 xl:h-full xl:min-h-0">
      {/* stage rail: driven by the investigation's real stage */}
      <div className="panel flex flex-wrap items-center gap-x-4 gap-y-2 px-3 py-2">
        <ol className="flex min-w-0 flex-1 items-center gap-1" aria-label="Analysis stages">
          {STAGES.map((s, i) => {
            const done = d.status === 'completed' || (stageIdx > i && d.status !== 'failed');
            const active = d.status === 'running' && stageIdx === i;
            return (
              <li key={s.id} className="flex min-w-0 flex-1 items-center gap-2" aria-current={active ? 'step' : undefined}>
                <span className={`relative h-[3px] flex-1 overflow-hidden ${done ? 'bg-cyan' : 'bg-line'}`}>{active && <span className="absolute inset-y-0 w-1/3 animate-sweep bg-amber" />}</span>
                <span className={`micro hidden shrink-0 md:inline ${active ? 'text-amber' : done ? 'text-titanium' : ''}`}>{s.label}</span>
              </li>
            );
          })}
        </ol>
        <div className="flex items-center gap-2">
          {d.status === 'created' && <button className="btn-primary" onClick={() => act(() => api(`/investigations/${id}/start`, { method: 'POST' }))}><Icon name="play" size={13} />Start analysis</button>}
          {(d.status === 'completed' || d.status === 'failed') && <button className="btn" onClick={() => act(() => api(`/investigations/${id}/start`, { method: 'POST' }))} title="Rebuild all derived data from the preserved originals">Re-run</button>}
          {d.status === 'completed' && <Link className="btn-primary" href={`/i/${id}/dossier`}><Icon name="report" size={13} />Open dossier</Link>}
          {d.status !== 'running' && <button className="btn-ghost px-2" aria-label="Delete investigation" onClick={() => { if (window.confirm(`Delete ${d.id} and all of its evidence? This cannot be undone.`)) act(async () => { await api(`/investigations/${id}`, { method: 'DELETE' }); router.push('/history'); }); }}><Icon name="trash" size={14} /></button>}
        </div>
        {(actionErr || d.error) && <p role="alert" className="w-full border-l-2 border-threat pl-2 text-data text-threat">{actionErr || `Analysis failed: ${d.error}`}</p>}
      </div>

      <div className="grid grid-cols-[minmax(0,1fr)] min-h-0 flex-1 gap-3 xl:grid-cols-[280px_minmax(0,1fr)_360px]">
        {/* left: evidence extraction + agent execution */}
        <div className="flex min-h-0 flex-col gap-3">
          <Panel title="Evidence" meta={`${d.evidence.length}`} className="xl:max-h-[46%]" bodyClass="overflow-auto">
            {d.evidence.length === 0 ? <Empty icon="evidence" title="No evidence">This case has no evidence. Open a new investigation to submit some.</Empty> : (
              <ul>{d.evidence.map((e) => (
                <li key={e.id} className="border-b border-line last:border-0">
                  <button className={`block w-full px-3 py-2 text-left hover:bg-elevated ${selected === `evidence:${e.id}` ? 'bg-elevated' : ''}`} onClick={() => setSelected(`evidence:${e.id}`)}>
                    <div className="flex items-center gap-2"><StatusDot status={e.status === 'parsed' ? 'completed' : e.status === 'failed' ? 'failed' : running ? 'running' : 'created'} /><span className="min-w-0 flex-1 truncate text-body text-paper">{e.name}</span></div>
                    <div className="micro mt-0.5 normal-case tracking-normal">{KIND_LABEL[e.kind] || e.kind} · {bytes(e.size_bytes)} · {e.status === 'parsed' ? 'extracted' : e.status === 'failed' ? 'could not be parsed' : 'stored, awaiting extraction'}</div>
                    <div className="micro mt-0.5 truncate normal-case tracking-normal text-titanium-faint">sha256 {e.sha256.slice(0, 24)}…</div>
                    {e.parse_error && <div className="mt-0.5 text-data text-threat">{e.parse_error}</div>}
                  </button>
                </li>))}</ul>
            )}
          </Panel>
          <Panel title="Agent execution" className="min-h-[180px] flex-1" bodyClass="overflow-auto">
            {d.agents.length === 0 ? <Empty title={d.status === 'created' ? 'Not started' : 'Waiting'}>{d.status === 'created' ? 'No agent has run. Start the analysis to dispatch them.' : 'The orchestrator has not recorded any execution yet.'}</Empty> : (
              <ul>{d.agents.map((a) => (
                <li key={a.id} className="border-b border-line px-3 py-1.5 last:border-0">
                  <div className="flex items-center gap-2"><StatusDot status={a.status} /><span className="text-body text-paper">{AGENT_LABEL[a.agent] || a.agent}</span>{a.attempt > 1 && <Tag>follow-up</Tag>}<span className={`micro ml-auto ${a.status === 'failed' ? 'text-threat' : a.status === 'running' ? 'text-amber' : ''}`}>{a.status}</span></div>
                  <div className="text-data text-titanium-mute">{a.task}</div>
                  {a.error && <div className="text-data text-threat">{a.error}</div>}
                </li>))}</ul>
            )}
          </Panel>
        </div>

        {/* centre: evidence environment */}
        <Panel title="Evidence environment" className="min-h-[420px]"
          actions={<div className="flex items-center gap-2"><Segmented label="Graph renderer" value={mode} onChange={setMode} options={[{ id: '3d', label: '3D' }, { id: '2d', label: '2D' }]} /><Link href={`/i/${id}/universe${selected ? `?focus=${encodeURIComponent(selected)}` : ''}`} className="btn h-7">Open universe</Link></div>}>
          <div className="relative h-full min-h-[380px]">
            {!graph ? <Loading label="Loading graph" /> : graph.nodes.length <= d.evidence.length && d.status === 'created'
              ? <Empty icon="universe" title="Nothing extracted yet" action={<button className="btn-primary" onClick={() => act(() => api(`/investigations/${id}/start`, { method: 'POST' }))}>Start analysis</button>}>The evidence is stored and hashed. Entities and relationships appear here as the Evidence Analyst extracts them.</Empty>
              : <GraphView graph={graph} view={DEFAULT_VIEW} mode={mode} selected={selected} onSelect={setSelected} compact />}
            {d.verdict && (
              <div className="pointer-events-none absolute left-3 top-3 max-w-[70%]">
                <VerdictBadge verdict={d.verdict} confidence={d.verdict_confidence} large />
                <div className="micro mt-1.5 normal-case tracking-normal">Derived from verified findings. No language model takes part in the verdict.</div>
              </div>
            )}
            {graph && <div className="micro pointer-events-none absolute bottom-3 right-3">{graph.counts.nodes} entities · {graph.counts.edges} relations</div>}
            <div className="pointer-events-none absolute bottom-3 left-3 flex gap-3">
              {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => (<div key={s} className="text-center"><div className={`font-display text-[20px] leading-none ${sevCount(s) ? (s === 'low' ? 'text-cyan' : s === 'medium' ? 'text-amber' : 'text-threat') : 'text-titanium-faint'}`}>{sevCount(s)}</div><div className="micro">{s}</div></div>))}
            </div>
          </div>
        </Panel>

        {/* right: live stream / inspector */}
        <div className="flex min-h-0 flex-col gap-3">
          <AnimatePresence mode="wait" initial={false}>
            {node && graph && ix ? (
              <motion.div key="insp" className="min-h-[320px] flex-1" initial={{ opacity: 0, x: 8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 8 }} transition={{ duration: 0.15 }}>
                <Panel title="Evidence inspector" className="h-full" actions={<button className="btn-ghost h-6 px-1" onClick={() => setSelected(null)} aria-label="Close inspector"><Icon name="close" size={13} /></button>}>
                  <EntityInspector node={node} graph={graph} ix={ix} findings={findings} caseId={id} onSelect={setSelected} />
                </Panel>
              </motion.div>
            ) : (
              <motion.div key="stream" className="min-h-[320px] flex-1" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.15 }}>
                <Panel title="Investigation activity" meta={running ? <span className="animate-blink text-amber">live</span> : `${events.length} events`} className="h-full">
                  <div ref={stream} className="h-full overflow-auto" role="log" aria-live="polite">
                    {events.length === 0 ? <Empty title="No activity recorded">{d.status === 'created' ? 'Activity appears here once analysis starts. Each line is written by the backend when the step actually happens.' : 'The backend has not emitted any event for this case.'}</Empty> : (
                      <ol>{events.map((e) => (
                        <li key={e.id} className="grid grid-cols-[58px_1fr] gap-2 border-b border-line px-3 py-1.5">
                          <time className="micro pt-0.5 normal-case tracking-normal" dateTime={e.at}>{utc(e.at, false)}</time>
                          <div><span className={`micro ${e.level === 'error' ? 'text-threat' : e.level === 'warn' ? 'text-amber' : 'text-cyan'}`}>{AGENT_LABEL[e.actor] || e.actor}</span><div className={`text-data ${e.level === 'error' ? 'text-threat' : 'text-titanium'}`}>{e.message}</div></div>
                        </li>))}</ol>
                    )}
                  </div>
                </Panel>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* findings */}
      <Panel title="Findings" meta={`${shown.length} shown`} className="shrink-0 xl:max-h-[38%]" bodyClass="overflow-auto"
        actions={<Segmented label="Finding filter" value={fFilter} onChange={setFFilter} options={[{ id: 'key', label: 'Key' }, { id: 'all', label: 'All verified' }, { id: 'rejected', label: `Rejected ${findings.filter((f) => f.verification_status === 'rejected').length}` }]} />}>
        {findings.length === 0 ? <Empty icon="alert" title={d.status === 'completed' ? 'No findings' : 'No findings yet'}>{d.status === 'completed' ? 'The detectors produced nothing for this evidence.' : 'Findings are listed here as detectors produce them, then marked verified or rejected by the Verifier.'}</Empty>
          : shown.length === 0 ? <Empty title="Nothing in this filter">{fFilter === 'key' ? 'No suspicious or malicious findings. Switch to “All verified” to see informational checks.' : fFilter === 'rejected' ? 'The Verifier rejected no findings.' : 'No verified findings.'}</Empty>
          : <div className="grid gap-x-6 gap-y-3 p-3 lg:grid-cols-2">{[...shown].sort((a, b) => SEV_ORDER.indexOf(b.severity) - SEV_ORDER.indexOf(a.severity)).map((f) => (<div key={f.id} id={f.id} className={focusFinding === f.id ? 'bg-amber-dim' : ''}><FindingCard f={f} caseId={id} onEvidence={(e) => setSelected(`evidence:${e}`)} /></div>))}</div>}
      </Panel>
    </div>
  );
}
