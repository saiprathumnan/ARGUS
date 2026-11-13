'use client';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import { useApi, usePersisted } from '@/lib/api';
import type { InvSummary } from '@/lib/types';
import { Empty, ErrorState, Icon, Loading, Panel, StatusDot, VerdictBadge } from '@/components/ui/kit';
import { utc, words } from '@/lib/format';

export default function History() {
  const [f, setF] = usePersisted<{ status: string; verdict: string }>('argus.historyFilter', { status: '', verdict: '' });
  const [q, setQ] = useState('');
  const [dq, setDq] = useState('');
  useEffect(() => { const t = setTimeout(() => setDq(q.trim()), 200); return () => clearTimeout(t); }, [q]);
  const qs = new URLSearchParams({ ...(dq ? { q: dq } : {}), ...(f.status ? { status: f.status } : {}), ...(f.verdict ? { verdict: f.verdict } : {}), limit: '200' }).toString();
  const list = useApi<InvSummary[]>(`/investigations?${qs}`, 5000);
  const filtered = !!(dq || f.status || f.verdict);
  return (
    <div className="mx-auto flex h-full max-w-[1400px] flex-col gap-3 p-3 lg:p-6">
      <div><div className="micro text-amber">Archive</div><h1 className="h-display mt-1 text-[26px]">Investigation history</h1></div>
      <div className="panel flex flex-wrap items-center gap-3 px-3 py-2">
        <div className="flex min-w-[220px] flex-1 items-center gap-2 border border-line-strong px-2"><Icon name="search" size={14} className="text-titanium-mute" /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by title, notes or case ID" aria-label="Search investigations" className="h-8 flex-1 bg-transparent text-data text-paper placeholder:text-titanium-faint focus:outline-none" /></div>
        <select className="field h-8 w-auto py-0 font-mono text-micro uppercase" value={f.status} onChange={(e) => setF((p) => ({ ...p, status: e.target.value }))} aria-label="Status"><option value="">any status</option>{['created', 'running', 'completed', 'failed'].map((s) => <option key={s} value={s}>{s}</option>)}</select>
        <select className="field h-8 w-auto py-0 font-mono text-micro uppercase" value={f.verdict} onChange={(e) => setF((p) => ({ ...p, verdict: e.target.value }))} aria-label="Verdict"><option value="">any verdict</option>{['malicious', 'suspicious', 'benign', 'insufficient_evidence'].map((s) => <option key={s} value={s}>{words(s)}</option>)}</select>
        {filtered && <button className="btn h-8" onClick={() => { setQ(''); setF({ status: '', verdict: '' }); }}>Clear</button>}
        <Link href="/new" className="btn-primary h-8"><Icon name="plus" size={13} />New</Link>
      </div>
      <Panel title="Investigations" meta={list.data ? `${list.data.length}` : undefined} className="min-h-0 flex-1" bodyClass="overflow-auto">
        {list.loading && !list.data ? <Loading /> : list.error ? <ErrorState error={list.error} retry={list.reload} /> : !list.data?.length ? (
          filtered ? <Empty icon="search" title="No investigation matches these filters" action={<button className="btn" onClick={() => { setQ(''); setF({ status: '', verdict: '' }); }}>Clear filters</button>} />
            : <Empty icon="history" title="The archive is empty" action={<Link href="/new" className="btn-primary">New investigation</Link>}>Completed and in-progress investigations are kept here with their evidence and reports.</Empty>
        ) : (
          <table className="w-full border-collapse text-left">
            <thead className="sticky top-0 z-10 bg-graphite"><tr className="micro border-b border-line">{['', 'Case', 'Status', 'Assessment', 'Evidence', 'Indicators', 'Findings', 'Created (UTC)', ''].map((h, i) => <th key={i} className="px-3 py-2 font-normal">{h}</th>)}</tr></thead>
            <tbody>{list.data.map((i) => (
              <tr key={i.id} className="border-b border-line hover:bg-elevated">
                <td className="w-6 px-3"><StatusDot status={i.status} /></td>
                <td className="max-w-[420px] px-3 py-2"><Link href={`/i/${i.id}`} className="block"><span className="block truncate text-body text-paper hover:text-cyan">{i.title}</span><span className="micro normal-case tracking-normal">{i.id}</span></Link></td>
                <td className="px-3 py-2"><span className={`micro ${i.status === 'running' ? 'text-amber' : i.status === 'failed' ? 'text-threat' : ''}`}>{i.status === 'running' ? words(i.stage) : i.status}</span></td>
                <td className="px-3 py-2"><VerdictBadge verdict={i.verdict} confidence={i.verdict_confidence} /></td>
                <td className="data px-3 py-2">{i.counts.evidence}</td><td className="data px-3 py-2">{i.counts.indicators}</td><td className="data px-3 py-2">{i.counts.findings}</td>
                <td className="data whitespace-nowrap px-3 py-2 text-titanium-mute">{utc(i.created_at)}</td>
                <td className="px-3 py-2 text-right">{i.status === 'completed' && <Link className="micro text-cyan hover:underline" href={`/i/${i.id}/dossier`}>dossier →</Link>}</td>
              </tr>))}</tbody>
          </table>)}
      </Panel>
    </div>
  );
}
