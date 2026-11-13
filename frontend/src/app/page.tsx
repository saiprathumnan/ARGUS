'use client';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { api, ApiError, useApi, useReducedMotion } from '@/lib/api';
import type { InvSummary, Scenario, Stage, SystemInfo } from '@/lib/types';
import { Empty, ErrorState, Icon, Loading, Panel, StatusDot, VerdictBadge } from '@/components/ui/kit';
import { utc, words } from '@/lib/format';

const Core = dynamic(() => import('@/components/three/IntelligenceCore'), { ssr: false, loading: () => <Loading label="Loading core" /> });
const STATE_COPY: Record<Stage, string> = {
  idle: 'No analysis is running.', evidence_collection: 'Parsing submitted evidence and extracting indicators.', processing: 'Analysing network activity and consulting intelligence sources.',
  correlation: 'Linking entities across evidence sources.', verification: 'Re-checking every finding against the preserved evidence.', completed: 'Last analysis completed.', failed: 'Last analysis failed.',
};

export default function Landing() {
  const router = useRouter();
  const reduced = useReducedMotion();
  const invs = useApi<InvSummary[]>('/investigations?limit=8', 3000);
  const sys = useApi<SystemInfo>('/system');
  const samples = useApi<Scenario[]>('/samples');
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const running = invs.data?.find((i) => i.status === 'running');
  // The core mirrors the engine: the running investigation's real stage, otherwise idle.
  const stage: Stage = running ? running.stage : 'idle';

  const loadSample = async (id: string) => {
    setBusy(id); setErr(null);
    try {
      const inv = await api<InvSummary>(`/samples/${id}`, { method: 'POST' });
      await api(`/investigations/${inv.id}/start`, { method: 'POST' });
      router.push(`/i/${inv.id}`);
    } catch (e) { setErr((e as ApiError).message); setBusy(null); }
  };

  return (
    <div className="grid-void min-h-full">
      <section className="relative mx-auto grid max-w-[1400px] items-center gap-6 px-5 pb-6 pt-8 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] lg:px-10 lg:pt-4">
        <div className="relative z-10">
          <div className="micro text-amber">Autonomous digital investigation engine</div>
          <h1 className="h-display mt-4 text-[44px] leading-[1.02] sm:text-[60px]">Raw artefacts in.<br />Verifiable findings out.</h1>
          <p className="mt-5 max-w-[46ch] text-[15px] leading-7 text-titanium">
            ARGUS parses suspicious emails, URLs, logs, captures and files, correlates what they share, and checks every conclusion against the original evidence before it reaches a report.
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link href="/new" className="btn-primary h-10 px-5"><Icon name="plus" />New investigation</Link>
            <Link href="/history" className="btn h-10 px-5">Investigation history</Link>
          </div>
          <dl className="mt-9 grid max-w-md grid-cols-[auto_1fr] gap-x-5 gap-y-1.5 border-t border-line pt-4">
            <dt className="micro pt-0.5">Engine state</dt>
            <dd className="flex items-center gap-2 text-body text-paper"><StatusDot status={running ? 'running' : invs.error ? 'failed' : 'created'} /><span className="font-mono uppercase tracking-wider">{invs.error ? 'offline' : words(stage)}</span></dd>
            <dt className="micro pt-0.5">Activity</dt>
            <dd className="text-body text-titanium">{invs.error ? invs.error.message : running ? <>{STATE_COPY[stage]} <Link className="text-cyan hover:underline" href={`/i/${running.id}`}>{running.id}</Link></> : STATE_COPY.idle}</dd>
            {sys.data && (<>
              <dt className="micro pt-0.5">Archive</dt><dd className="data">{sys.data.totals.investigations} investigations · {sys.data.totals.evidence} evidence items</dd>
              <dt className="micro pt-0.5">Intelligence</dt><dd className="data">{sys.data.threat_intel.offline_mode ? 'offline · bundled sample data' : sys.data.threat_intel.providers.filter((p) => p.enabled).map((p) => p.name).join(', ')}</dd>
            </>)}
          </dl>
        </div>
        <div className="relative h-[340px] sm:h-[460px] lg:h-[560px]">
          <Core stage={stage} reducedMotion={reduced} className="absolute inset-0" />
          <div className="pointer-events-none absolute bottom-2 left-1/2 -translate-x-1/2 text-center">
            <div className="micro">Intelligence core · mirrors backend state</div>
          </div>
        </div>
      </section>

      <section className="mx-auto grid max-w-[1400px] gap-4 px-5 pb-10 lg:grid-cols-2 lg:px-10">
        <Panel title="Recent investigations" meta={invs.data ? `${invs.data.length} shown` : undefined} bodyClass="overflow-auto">
          {invs.loading && !invs.data ? <Loading /> : invs.error ? <ErrorState error={invs.error} retry={invs.reload} /> : !invs.data?.length ? (
            <Empty icon="workspace" title="No investigations yet" action={<Link href="/new" className="btn-primary">Start the first one</Link>}>Create an investigation and submit evidence, or run one of the bundled sample scenarios.</Empty>
          ) : (
            <ul>
              {invs.data.map((i) => (
                <li key={i.id} className="border-b border-line last:border-0">
                  <Link href={`/i/${i.id}`} className="flex items-center gap-3 px-3 py-2.5 hover:bg-elevated">
                    <StatusDot status={i.status} />
                    <div className="min-w-0 flex-1"><div className="truncate text-body text-paper">{i.title}</div><div className="micro normal-case tracking-normal">{i.id} · {utc(i.created_at)} UTC · {i.counts.evidence} evidence · {i.counts.findings} findings</div></div>
                    {i.status === 'running' ? <span className="micro text-amber">{words(i.stage)}</span> : <VerdictBadge verdict={i.verdict} />}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="Bundled sample scenarios" meta="synthetic data" bodyClass="overflow-auto">
          {samples.loading ? <Loading /> : samples.error ? <ErrorState error={samples.error} retry={samples.reload} /> : !samples.data?.length ? (
            <Empty title="No sample datasets installed">Run <code className="data">python scripts/generate_samples.py</code> in the backend to create them.</Empty>
          ) : (
            <>
              <p className="border-b border-line px-3 py-2 text-data text-titanium-mute">Reproducible, harmless datasets with known expected outcomes. Loading one creates a real investigation and runs the full pipeline on it.</p>
              {err && <p role="alert" className="border-b border-line px-3 py-2 text-data text-threat">{err}</p>}
              <ul>
                {samples.data.map((s) => (
                  <li key={s.id} className="flex items-center gap-3 border-b border-line px-3 py-2 last:border-0">
                    <div className="min-w-0 flex-1"><div className="truncate text-body text-paper">{s.title}</div><div className="micro normal-case tracking-normal">{s.evidence.map((e) => e.kind).join(' + ')} · expected: {words(s.expected_verdict)}</div></div>
                    <button className="btn h-7" disabled={!!busy} onClick={() => loadSample(s.id)}>{busy === s.id ? 'Starting…' : 'Run'}<Icon name="arrow" size={13} /></button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Panel>
      </section>
    </div>
  );
}
