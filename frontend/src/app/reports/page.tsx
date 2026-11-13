'use client';
import Link from 'next/link';
import { useApi } from '@/lib/api';
import { Empty, ErrorState, Loading, Panel, VerdictBadge } from '@/components/ui/kit';
import { utc } from '@/lib/format';

interface Row { id: string; investigation_id: string; title: string; version: number; created_at: string; verdict: string | null; confidence: number | null; findings: number; narrative_source: string }

export default function Reports() {
  const list = useApi<Row[]>('/reports', 8000);
  return (
    <div className="mx-auto flex h-full max-w-[1400px] flex-col gap-3 p-3 lg:p-6">
      <div><div className="micro text-amber">Archive</div><h1 className="h-display mt-1 text-[26px]">Forensic reports</h1></div>
      <Panel title="Generated dossiers" meta={list.data ? `${list.data.length}` : undefined} className="min-h-0 flex-1" bodyClass="overflow-auto">
        {list.loading && !list.data ? <Loading /> : list.error ? <ErrorState error={list.error} retry={list.reload} /> : !list.data?.length ? (
          <Empty icon="report" title="No reports yet" action={<Link href="/new" className="btn-primary">New investigation</Link>}>A dossier is written at the end of every completed analysis.</Empty>
        ) : (
          <table className="w-full border-collapse text-left">
            <thead className="sticky top-0 bg-graphite"><tr className="micro border-b border-line">{['Report', 'Case', 'Assessment', 'Findings', 'Narrative', 'Generated (UTC)', 'Export'].map((h) => <th key={h} className="px-3 py-2 font-normal">{h}</th>)}</tr></thead>
            <tbody>{list.data.map((r) => (
              <tr key={r.id} className="border-b border-line hover:bg-elevated">
                <td className="px-3 py-2"><Link href={`/i/${r.investigation_id}/dossier`} className="data text-cyan hover:underline">{r.id}</Link> <span className="micro">v{r.version}</span></td>
                <td className="max-w-[360px] px-3 py-2"><Link href={`/i/${r.investigation_id}`} className="block truncate text-body text-paper hover:text-cyan">{r.title}</Link><span className="micro normal-case tracking-normal">{r.investigation_id}</span></td>
                <td className="px-3 py-2"><VerdictBadge verdict={r.verdict} confidence={r.confidence} /></td>
                <td className="data px-3 py-2">{r.findings}</td>
                <td className="px-3 py-2 text-data text-titanium-mute">{r.narrative_source === 'deterministic_template' ? 'template' : 'language model, verified'}</td>
                <td className="data whitespace-nowrap px-3 py-2 text-titanium-mute">{utc(r.created_at)}</td>
                <td className="whitespace-nowrap px-3 py-2">{(['html', 'md', 'json'] as const).map((f) => <a key={f} className="micro mr-3 text-cyan hover:underline" href={`/api/investigations/${r.investigation_id}/report/export?format=${f}`} target={f === 'html' ? '_blank' : undefined} rel="noreferrer" download={f === 'html' ? undefined : true}>{f}</a>)}</td>
              </tr>))}</tbody>
          </table>)}
      </Panel>
    </div>
  );
}
