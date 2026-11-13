'use client';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useMemo, useState } from 'react';
import { useApi, usePersisted } from '@/lib/api';
import type { EvidenceItem, Finding, IndicatorRow, InvDetail } from '@/lib/types';
import { FindingCard } from '@/components/Inspector';
import { Empty, ErrorState, Icon, KV, Loading, Panel, Segmented, SeverityTag, StatusDot, Tag } from '@/components/ui/kit';
import { bytes, KIND_LABEL, pct, short, TYPE_LABEL, utc, words } from '@/lib/format';

interface Detail extends EvidenceItem { indicators: { id: string; type: string; value: string; context: string; first_seen: string | null }[]; events: { id: string; at: string | null; category: string; action: string; outcome: string | null; summary: string; record_ref: string; duplicate_of: string | null }[]; event_total: number; findings: Finding[]; relationships: { id: string; source: string; target: string; relation: string; basis: string; confidence: number; explanation: string; count: number }[] }

function Meta({ meta }: { meta: Record<string, any> }) {
  const rows = Object.entries(meta).filter(([, v]) => v !== null && v !== '' && !(Array.isArray(v) && v.length === 0));
  if (!rows.length) return <p className="text-data text-titanium-mute">No metadata extracted yet.</p>;
  return <dl>{rows.map(([k, v]) => (<KV key={k} k={words(k)}>{typeof v === 'object' ? <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all text-[11px] leading-4 text-titanium">{JSON.stringify(v, null, 1)}</pre> : String(v)}</KV>))}</dl>;
}

export default function EvidenceExplorer({ params }: { params: { id: string } }) {
  const id = params.id;
  const sp = useSearchParams();
  const inv = useApi<InvDetail>(`/investigations/${id}`, 4000);
  const [tab, setTab] = usePersisted<'evidence' | 'indicators'>(`argus.${id}.evTab`, 'evidence');
  const [pick, setPick] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [type, setType] = useState('');
  const current = pick || sp.get('e') || inv.data?.evidence[0]?.id || null;
  const det = useApi<Detail>(current ? `/investigations/${id}/evidence/${current}` : null);
  const inds = useApi<IndicatorRow[]>(tab === 'indicators' ? `/investigations/${id}/indicators` : null);
  const [sub, setSub] = useState<'overview' | 'indicators' | 'events' | 'relations' | 'findings'>('overview');
  const evFiltered = useMemo(() => (inv.data?.evidence || []).filter((e) => !q || [e.name, e.sha256, e.id, e.kind].some((s) => s.toLowerCase().includes(q.toLowerCase()))), [inv.data, q]);
  const indFiltered = useMemo(() => (inds.data || []).filter((i) => (!type || i.type === type) && (!q || i.value.toLowerCase().includes(q.toLowerCase()))), [inds.data, q, type]);

  if (inv.loading && !inv.data) return <Loading label="Opening case" />;
  if (inv.error && !inv.data) return <ErrorState error={inv.error} retry={inv.reload} />;

  return (
    <div className="flex h-full min-h-[600px] flex-col gap-3 p-3">
      <div className="panel flex flex-wrap items-center gap-3 px-3 py-2">
        <Segmented label="Explorer mode" value={tab} onChange={(v) => { setTab(v); setQ(''); }} options={[{ id: 'evidence', label: 'Evidence items' }, { id: 'indicators', label: 'Indicators' }]} />
        <div className="flex min-w-[220px] flex-1 items-center gap-2 border border-line-strong px-2"><Icon name="search" size={14} className="text-titanium-mute" /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder={tab === 'evidence' ? 'Filter by name, hash, id or kind' : 'Filter indicator values'} aria-label="Filter" className="h-8 flex-1 bg-transparent text-data text-paper placeholder:text-titanium-faint focus:outline-none" /></div>
        {tab === 'indicators' && <select className="field h-8 w-auto py-0 font-mono text-micro uppercase" value={type} onChange={(e) => setType(e.target.value)} aria-label="Indicator type"><option value="">all types</option>{['ip', 'domain', 'url', 'email', 'sha256', 'user', 'host'].map((t) => <option key={t} value={t}>{TYPE_LABEL[t]}</option>)}</select>}
      </div>

      {tab === 'indicators' ? (
        <Panel title="Extracted indicators" meta={inds.data ? `${indFiltered.length} of ${inds.data.length}` : undefined} className="min-h-0 flex-1" bodyClass="overflow-auto">
          {inds.loading ? <Loading /> : inds.error ? <ErrorState error={inds.error} retry={inds.reload} /> : !inds.data?.length ? <Empty icon="search" title="No indicators">Indicators are extracted during analysis. {inv.data?.status === 'created' ? 'This case has not been analysed yet.' : ''}</Empty>
            : !indFiltered.length ? <Empty title="No indicator matches the filter" /> : (
              <table className="w-full border-collapse text-left">
                <thead className="sticky top-0 bg-graphite"><tr className="micro border-b border-line">{['Type', 'Value', 'Severity', 'Sources', 'Reputation', 'First seen (UTC)', ''].map((h) => <th key={h} className="px-3 py-2 font-normal">{h}</th>)}</tr></thead>
                <tbody>{indFiltered.slice(0, 500).map((i) => (
                  <tr key={`${i.type}:${i.value}`} className="border-b border-line hover:bg-elevated">
                    <td className="px-3 py-1.5"><Tag>{i.type}</Tag></td>
                    <td className="data max-w-[420px] break-all px-3 py-1.5 text-paper" title={i.contexts.join(' · ')}>{i.value}</td>
                    <td className="px-3 py-1.5"><SeverityTag severity={i.max_severity} /></td>
                    <td className="data px-3 py-1.5">{[...new Set(i.evidence_ids)].map((e) => (<button key={e} className="mr-2 text-cyan hover:underline" onClick={() => { setTab('evidence'); setPick(e); setQ(''); }}>{e.slice(4, 10)}</button>))}</td>
                    <td className="px-3 py-1.5 text-data">{i.intel.length ? i.intel.map((t, k) => <span key={k} className={`mr-2 ${t.verdict === 'malicious' ? 'text-threat' : t.verdict === 'clean' ? 'text-cyan' : 'text-amber'}`} title={`${t.summary} · queried ${utc(t.queried_at)}`}>{t.verdict} · {t.source}</span>) : <span className="text-titanium-faint">no record</span>}</td>
                    <td className="data px-3 py-1.5 text-titanium-mute">{utc(i.first_seen)}</td>
                    <td className="px-3 py-1.5 text-right"><Link className="micro text-cyan hover:underline" href={`/i/${id}/universe?focus=${encodeURIComponent(`${i.type}:${i.value}`)}`}>graph →</Link></td>
                  </tr>))}</tbody>
              </table>)}
          {indFiltered.length > 500 && <p className="micro p-3 normal-case tracking-normal">Showing the first 500 matches. Narrow the filter to see the rest.</p>}
        </Panel>
      ) : (
        <div className="grid grid-cols-[minmax(0,1fr)] min-h-0 flex-1 gap-3 lg:grid-cols-[320px_minmax(0,1fr)]">
          <Panel title="Evidence items" meta={`${evFiltered.length}`} bodyClass="overflow-auto">
            {!inv.data?.evidence.length ? <Empty icon="evidence" title="No evidence in this case" /> : !evFiltered.length ? <Empty title="No evidence matches the filter" /> : (
              <ul>{evFiltered.map((e) => (
                <li key={e.id} className="border-b border-line">
                  <button className={`relative block w-full px-3 py-2 text-left hover:bg-elevated ${current === e.id ? 'bg-elevated' : ''}`} onClick={() => { setPick(e.id); setSub('overview'); }} aria-current={current === e.id}>
                    {current === e.id && <span className="absolute inset-y-0 left-0 w-[2px] bg-amber" />}
                    <div className="flex items-center gap-2"><StatusDot status={e.status === 'parsed' ? 'completed' : e.status === 'failed' ? 'failed' : 'created'} /><span className="min-w-0 flex-1 truncate text-body text-paper">{e.name}</span></div>
                    <div className="micro mt-0.5 normal-case tracking-normal">{e.id} · {KIND_LABEL[e.kind] || e.kind} · {bytes(e.size_bytes)}</div>
                  </button>
                </li>))}</ul>)}
          </Panel>
          <Panel title={det.data ? det.data.name : 'Evidence detail'} meta={det.data?.id} bodyClass="flex flex-col min-h-0">
            {!current ? <Empty icon="evidence" title="Select an evidence item" /> : det.loading && !det.data ? <Loading /> : det.error ? <ErrorState error={det.error} retry={det.reload} /> : det.data && (
              <>
                <div className="flex flex-wrap gap-1 border-b border-line px-3 py-2" role="tablist">
                  {([['overview', 'Overview'], ['indicators', `Indicators ${det.data.indicators.length}`], ['events', `Events ${det.data.event_total}`], ['relations', `Relationships ${det.data.relationships.length}`], ['findings', `Findings ${det.data.findings.length}`]] as const).map(([k, l]) => (
                    <button key={k} role="tab" aria-selected={sub === k} onClick={() => setSub(k)} className={`h-7 border px-2.5 font-mono text-micro uppercase ${sub === k ? 'border-titanium text-paper' : 'border-transparent text-titanium-mute hover:text-paper'}`}>{l}</button>))}
                </div>
                <div className="min-h-0 flex-1 overflow-auto p-3">
                  {sub === 'overview' && (
                    <div className="grid gap-6 xl:grid-cols-2">
                      <div><div className="micro mb-1 text-amber">Provenance</div><dl>
                        <KV k="Evidence ID">{det.data.id}</KV><KV k="Kind">{KIND_LABEL[det.data.kind] || det.data.kind}</KV><KV k="Original name">{det.data.name}</KV>
                        <KV k="SHA-256">{det.data.sha256}</KV><KV k="Size">{bytes(det.data.size_bytes)} ({det.data.size_bytes} bytes)</KV><KV k="Content type">{det.data.mime_type}</KV>
                        <KV k="Entered via">{words(det.data.source)}</KV><KV k="Submitted by">{det.data.submitted_by}</KV><KV k="Ingested (UTC)">{utc(det.data.ingested_at)}</KV>
                        <KV k="Status">{det.data.status}{det.data.parse_error ? ` — ${det.data.parse_error}` : ''}</KV>
                      </dl><p className="micro mt-2 normal-case tracking-normal">The original bytes are preserved read-only. The Verifier re-hashes them before accepting any finding that cites this item.</p></div>
                      <div><div className="micro mb-1 text-amber">Extracted metadata</div><Meta meta={det.data.meta || {}} /></div>
                    </div>)}
                  {sub === 'indicators' && (!det.data.indicators.length ? <Empty title="No indicators extracted from this item" /> : (
                    <table className="w-full border-collapse text-left"><thead><tr className="micro border-b border-line"><th className="py-1.5 pr-3 font-normal">Type</th><th className="py-1.5 pr-3 font-normal">Value</th><th className="py-1.5 font-normal">Where it was found</th></tr></thead>
                      <tbody>{det.data.indicators.map((i) => (<tr key={i.id} className="border-b border-line"><td className="py-1.5 pr-3"><Tag>{i.type}</Tag></td><td className="data break-all py-1.5 pr-3"><Link className="text-paper hover:text-cyan" href={`/i/${id}/universe?focus=${encodeURIComponent(`${i.type}:${i.value}`)}`}>{i.value}</Link></td><td className="py-1.5 text-data text-titanium-mute">{i.context}</td></tr>))}</tbody></table>))}
                  {sub === 'events' && (!det.data.events.length ? <Empty title="No normalised events from this item" /> : (<>
                    <table className="w-full border-collapse text-left"><thead><tr className="micro border-b border-line"><th className="py-1.5 pr-3 font-normal">Time (UTC)</th><th className="py-1.5 pr-3 font-normal">Category</th><th className="py-1.5 pr-3 font-normal">Summary</th><th className="py-1.5 font-normal">Record</th></tr></thead>
                      <tbody>{det.data.events.map((e) => (<tr key={e.id} className={`border-b border-line ${e.duplicate_of ? 'opacity-50' : ''}`}><td className="data whitespace-nowrap py-1.5 pr-3 text-titanium-mute">{utc(e.at)}</td><td className="py-1.5 pr-3"><Tag>{e.category}</Tag></td><td className="py-1.5 pr-3 text-data">{e.summary}{e.duplicate_of && <span className="text-amber"> · duplicate of {e.duplicate_of}</span>}</td><td className="data py-1.5 text-titanium-mute">{short(e.record_ref, 36)}</td></tr>))}</tbody></table>
                    {det.data.event_total > det.data.events.length && <p className="micro mt-2 normal-case tracking-normal">Showing the first {det.data.events.length} of {det.data.event_total} events.</p>}</>))}
                  {sub === 'relations' && (!det.data.relationships.length ? <Empty title="No relationships are supported by this item" /> : (
                    <ul>{det.data.relationships.map((r) => (<li key={r.id} className="border-b border-line py-1.5"><div className="flex flex-wrap items-center gap-2"><span className="data break-all">{short(r.source, 48)}</span><span className="micro text-amber">→ {words(r.relation)} →</span><span className="data break-all">{short(r.target, 48)}</span><Tag tone={r.basis === 'inferred' ? 'amber' : 'default'}>{r.basis}</Tag><span className="micro">conf {pct(r.confidence)}{r.count > 1 ? ` · ×${r.count}` : ''}</span></div><div className="text-data text-titanium-mute">{r.explanation}</div></li>))}</ul>))}
                  {sub === 'findings' && (!det.data.findings.length ? <Empty title="No finding cites this item" /> : <div className="space-y-3">{det.data.findings.map((f) => <FindingCard key={f.id} f={f} caseId={id} onEvidence={(e) => { setPick(e); setSub('overview'); }} />)}</div>)}
                </div>
              </>)}
          </Panel>
        </div>
      )}
    </div>
  );
}
