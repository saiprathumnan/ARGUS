'use client';
import Link from 'next/link';
import { useApi } from '@/lib/api';
import type { InvDetail, Report } from '@/lib/types';
import { Empty, ErrorState, Icon, Loading } from '@/components/ui/kit';
import { bytes, KIND_LABEL, pct, utc, VERDICT, words } from '@/lib/format';

const SEV_PRINT: Record<string, string> = { critical: '#b3202b', high: '#b3202b', medium: '#b06a12', low: '#157a86', info: '#7C8796' };

function H2({ n, children }: { n: string; children: React.ReactNode }) {
  return (<h2 className="mb-3 mt-10 flex items-center gap-3 border-t border-line-strong pt-3 print:border-[#151A22]"><span className="font-mono text-[10px] tracking-[0.16em] text-amber print:text-[#b06a12]">{n}</span><span className="font-display text-[11px] font-semibold uppercase tracking-[0.18em] text-titanium print:text-[#151A22]">{children}</span></h2>);
}
const Ref = ({ children }: { children: React.ReactNode }) => <span className="font-mono text-[10.5px] text-titanium-mute print:text-[#5b6675]">{children}</span>;
const th = 'border-b border-line-strong px-2 py-1.5 text-left font-mono text-[9.5px] font-normal uppercase tracking-[0.12em] text-titanium-mute print:border-[#151A22] print:text-[#5b6675]';
const td = 'border-b border-line px-2 py-1.5 align-top text-[12px] leading-[18px] print:border-[#d9dee5]';

export default function Dossier({ params }: { params: { id: string } }) {
  const id = params.id;
  const inv = useApi<InvDetail>(`/investigations/${id}`, 4000);
  const rep = useApi<Report>(inv.data?.status === 'completed' ? `/investigations/${id}/report?v=${inv.data.completed_at}` : null);

  if (inv.loading && !inv.data) return <Loading label="Opening case" />;
  if (inv.error && !inv.data) return <ErrorState error={inv.error} retry={inv.reload} />;
  if (inv.data?.status !== 'completed') return (<div className="p-6"><Empty icon="report" title={inv.data?.status === 'running' ? 'The report is not ready yet' : inv.data?.status === 'failed' ? 'Analysis failed before a report was produced' : 'No report yet'}
    action={<Link href={`/i/${id}`} className="btn">Go to workspace</Link>}>{inv.data?.status === 'running' ? 'The Report Generator runs last, after verification. This page will show the dossier as soon as it is written.' : inv.data?.status === 'failed' ? inv.data.error : 'A dossier is generated when an analysis completes.'}</Empty></div>);
  if (rep.loading && !rep.data) return <Loading label="Loading dossier" />;
  if (rep.error) return <ErrorState error={rep.error} retry={rep.reload} />;
  const c = rep.data!.content;
  const v = VERDICT[c.verdict.value] || VERDICT.insufficient_evidence;
  const techniques = Object.values((c.mitre as any[]).reduce((acc: Record<string, any>, m) => { (acc[m.technique_id] ||= { ...m, rationales: [] }).rationales.push({ r: m.rationale, f: m.finding_id }); return acc; }, {}));

  return (
    <div className="print-root min-h-full bg-obsidian px-3 py-4 sm:px-6">
      <div className="no-print mx-auto mb-3 flex max-w-[900px] flex-wrap items-center gap-2">
        <span className="micro">Report v{rep.data!.version} · generated {utc(rep.data!.created_at)} UTC</span>
        <div className="ml-auto flex flex-wrap gap-2">
          <button className="btn-primary" onClick={() => window.print()}><Icon name="print" size={13} />Print / save as PDF</button>
          {(['html', 'md', 'json'] as const).map((f) => <a key={f} className="btn" href={`/api/investigations/${id}/report/export?format=${f}`} target={f === 'html' ? '_blank' : undefined} rel="noreferrer" download={f === 'html' ? undefined : true}>{f.toUpperCase()}</a>)}
        </div>
      </div>

      <article className="dossier panel-solid mx-auto max-w-[900px] px-6 py-8 text-titanium sm:px-12 sm:py-12">
        <header className="border-b-2 border-titanium pb-6 print:border-[#151A22]">
          <div className="flex items-center justify-between"><span className="font-mono text-[10px] uppercase tracking-[0.22em] text-amber print:text-[#b06a12]">ARGUS · Forensic dossier</span><Ref>{c.metadata.investigation_id}</Ref></div>
          <h1 className="h-display mt-5 text-[34px] leading-[1.08] print:text-[#151A22]">{c.metadata.title}</h1>
          {c.metadata.description && <p className="mt-2 max-w-[70ch] text-body">{c.metadata.description}</p>}
          <div className="mt-6 flex flex-wrap items-end gap-x-10 gap-y-4">
            <div><div className="micro print:text-[#5b6675]">Assessment</div><div className="mt-1 font-display text-[22px]" style={{ color: v.hex === '#B9C2CE' ? undefined : v.hex }}>{c.verdict.label}</div></div>
            <div><div className="micro print:text-[#5b6675]">Confidence</div><div className="mt-1 font-display text-[22px] text-paper print:text-[#151A22]">{pct(c.verdict.confidence)}</div></div>
            <div><div className="micro print:text-[#5b6675]">Evidence items</div><div className="mt-1 font-display text-[22px] text-paper print:text-[#151A22]">{c.evidence.length}</div></div>
            <div><div className="micro print:text-[#5b6675]">Verified findings</div><div className="mt-1 font-display text-[22px] text-paper print:text-[#151A22]">{c.verification?.verified ?? c.findings.length}</div></div>
          </div>
          <p className="mt-3 text-[11.5px] text-titanium-mute print:text-[#5b6675]">{c.verdict.rule}</p>
        </header>

        <H2 n="01">Executive summary</H2>
        <div className="space-y-2 text-[14px] leading-6 text-paper print:text-[#151A22]">{c.executive_summary.map((s: any, i: number) => (<p key={i}>{s.text}{s.finding_ids.length > 0 && <> <Ref>[{s.finding_ids.join(', ')}]</Ref></>}</p>))}</div>

        <H2 n="02">Investigation metadata</H2>
        <table className="w-full border-collapse"><tbody>
          {[['Investigation', c.metadata.investigation_id], ['Created (UTC)', utc(c.metadata.created_at)], ['Analysis started (UTC)', utc(c.metadata.analysis_started)], ['Report generated (UTC)', utc(c.metadata.report_generated)], ['Engine', c.metadata.engine], ['Narrative source', c.metadata.narrative_source],
            ['Configuration', `live URL fetch ${c.metadata.configuration.network_fetch ? 'on' : 'off'} · threat intel ${c.metadata.configuration.intel_offline ? 'offline (sample bundle)' : 'online'} · language model ${c.metadata.configuration.llm_provider}`]].map(([k, val]) => (<tr key={k}><td className={`${td} w-[190px] font-mono text-[10.5px] uppercase tracking-[0.1em] text-titanium-mute print:text-[#5b6675]`}>{k}</td><td className={td}>{val}</td></tr>))}
        </tbody></table>

        <H2 n="03">Evidence references</H2>
        <table className="w-full border-collapse"><thead><tr><th className={th}>ID</th><th className={th}>Kind</th><th className={th}>Name</th><th className={th}>SHA-256</th><th className={th}>Ingested (UTC)</th></tr></thead>
          <tbody>{c.evidence.map((e: any) => (<tr key={e.id} className="avoid-break"><td className={`${td} whitespace-nowrap font-mono text-[10.5px]`}>{e.id}</td><td className={td}>{KIND_LABEL[e.kind] || e.kind}</td><td className={`${td} break-all`}>{e.name} <Ref>({bytes(e.size_bytes)}{e.status !== 'parsed' ? `, ${e.status}` : ''})</Ref></td><td className={`${td} break-all font-mono text-[10px]`}>{e.sha256}</td><td className={`${td} whitespace-nowrap font-mono text-[10.5px]`}>{utc(e.ingested_at)}</td></tr>))}</tbody></table>
        {c.verification?.evidence_integrity && <p className="mt-2 text-[11.5px] text-titanium-mute print:text-[#5b6675]">Integrity: the Verifier re-hashed every stored original before accepting findings — {Object.values(c.verification.evidence_integrity).every(Boolean) ? 'all hashes matched.' : 'ONE OR MORE HASHES DID NOT MATCH; affected findings were rejected.'}</p>}

        <H2 n="04">Findings</H2>
        {c.findings.length === 0 ? <p className="text-body text-titanium-mute">No findings above informational level.</p> : (
          <div className="space-y-5">{c.findings.map((f: any) => (
            <section key={f.id} className="avoid-break border-l-[3px] pl-4" style={{ borderColor: SEV_PRINT[f.severity] }}>
              <h3 className="text-[14px] font-semibold leading-5 text-paper print:text-[#151A22]">{f.title}</h3>
              <div className="mt-1 flex flex-wrap gap-x-4 font-mono text-[10px] uppercase tracking-[0.1em] text-titanium-mute print:text-[#5b6675]"><span style={{ color: SEV_PRINT[f.severity] }}>{f.severity}</span><span>{words(f.classification)}</span><span>basis: {words(f.basis)}</span><span>confidence {pct(f.confidence)}</span></div>
              <p className="mt-1.5 text-[12.5px] leading-[19px]">{f.description}</p>
              <p className="mt-1"><Ref>{f.id} · evidence {f.evidence_ids.join(', ')} · verifier: {f.verification_status} — {f.verification_notes}</Ref></p>
            </section>))}</div>)}
        {c.benign_checks.length > 0 && <p className="mt-4 text-[12px] text-titanium-mute print:text-[#5b6675]">{c.benign_checks.length} check(s) completed without indicators: {c.benign_checks.map((b: any) => b.title).join('; ')}.</p>}
        {c.rejected_findings.length > 0 && <div className="avoid-break mt-4 border border-threat/40 p-3"><div className="micro text-threat">Rejected by the Verifier ({c.rejected_findings.length}) — excluded from the assessment</div><ul className="mt-1 space-y-1">{c.rejected_findings.map((r: any) => <li key={r.id} className="text-[12px]"><span className="line-through">{r.title}</span> — {r.reason}</li>)}</ul></div>}

        <H2 n="05">Timeline</H2>
        {c.timeline.attack_sequence && (<div className="avoid-break mb-4 border border-amber/40 p-3 print:border-[#b06a12]"><div className="font-mono text-[10px] uppercase tracking-[0.14em] text-amber print:text-[#b06a12]">Inferred attack sequence — hypothesis, not observation</div><p className="mt-1 text-[12px]">{c.timeline.attack_sequence.basis}</p>
          <ol className="mt-2 space-y-1">{c.timeline.attack_sequence.steps.map((s: any, i: number) => (<li key={i} className="grid grid-cols-[150px_150px_1fr] gap-2 text-[12px]"><span className="font-mono text-[10.5px]">{s.at ? utc(s.at) : 'untimed'}</span><span className="font-mono text-[10.5px] uppercase tracking-[0.08em]">{words(s.phase)}</span><span>{s.title} <Ref>[{s.finding_id}]</Ref></span></li>))}</ol></div>)}
        {c.timeline.notable_events.length === 0 ? <p className="text-body text-titanium-mute">No dated events are tied to findings.</p> : (
          <table className="w-full border-collapse"><thead><tr><th className={th}>Time (UTC)</th><th className={th}>Layer</th><th className={th}>Event</th><th className={th}>Time basis</th></tr></thead>
            <tbody>{c.timeline.notable_events.map((t: any) => (<tr key={t.id} className="avoid-break"><td className={`${td} whitespace-nowrap font-mono text-[10.5px]`}>{utc(t.at)}</td><td className={td}>{t.layer}</td><td className={td}>{t.summary} <Ref>[{t.evidence_id} · {t.record_ref}]</Ref></td><td className={`${td} whitespace-nowrap`} style={{ color: t.time_basis === 'confirmed' ? undefined : '#b06a12' }}>{words(t.time_basis)}</td></tr>))}</tbody></table>)}
        <p className="mt-2 text-[11.5px] text-titanium-mute print:text-[#5b6675]">{c.timeline.notable_events.length} event(s) tied to findings are listed, out of {c.timeline.total_events} extracted.</p>

        <H2 n="06">MITRE ATT&amp;CK mapping</H2>
        {techniques.length === 0 ? <p className="text-body text-titanium-mute">No technique met the evidence bar for mapping.</p> : (
          <table className="w-full border-collapse"><thead><tr><th className={th}>Technique</th><th className={th}>Tactics</th><th className={th}>Why it applies</th></tr></thead>
            <tbody>{(techniques as any[]).map((m) => (<tr key={m.technique_id} className="avoid-break"><td className={`${td} w-[210px]`}><span className="font-mono text-[10.5px]">{m.technique_id}</span><br />{m.technique_name}</td><td className={`${td} w-[130px]`}>{m.tactics.map((t: string) => t.replace(/-/g, ' ')).join(', ')}</td><td className={td}>{m.rationales.map((r: any, i: number) => <span key={i} className="block">{r.r} <Ref>[{r.f}]</Ref></span>)}</td></tr>))}</tbody></table>)}

        {c.threat_intelligence.length > 0 && (<><H2 n="07">Threat intelligence</H2><p className="mb-2 text-[12px] text-titanium-mute print:text-[#5b6675]">Reputation data is third-party opinion with the source and query time recorded. It is not evidence from this investigation.</p>
          <table className="w-full border-collapse"><thead><tr><th className={th}>Indicator</th><th className={th}>Source</th><th className={th}>Verdict</th><th className={th}>Summary</th><th className={th}>Queried (UTC)</th></tr></thead>
            <tbody>{c.threat_intelligence.map((t: any, i: number) => (<tr key={i} className="avoid-break"><td className={`${td} break-all font-mono text-[10.5px]`}>{t.indicator}</td><td className={td}>{t.source} <Ref>({t.reliability})</Ref></td><td className={td}>{t.verdict}</td><td className={td}>{t.summary}</td><td className={`${td} whitespace-nowrap font-mono text-[10.5px]`}>{utc(t.queried_at)}</td></tr>))}</tbody></table></>)}

        <H2 n="08">Confidence and limitations</H2>
        <ul className="list-disc space-y-1.5 pl-5 text-[12.5px] leading-[19px]">{c.confidence_and_limitations.map((l: string, i: number) => <li key={i}>{l}</li>)}</ul>
        {c.verification?.conflicts?.length > 0 && <div className="avoid-break mt-3"><div className="micro text-amber print:text-[#b06a12]">Conflicting evidence</div><ul className="mt-1 list-disc space-y-1 pl-5 text-[12.5px]">{c.verification.conflicts.map((x: any, i: number) => <li key={i}><span className="font-mono text-[10.5px]">{x.indicator}</span>: {x.conflict} <Ref>[{x.finding_id}]</Ref></li>)}</ul></div>}

        <H2 n="09">Recommended actions</H2>
        {c.recommended_actions.length === 0 ? <p className="text-body text-titanium-mute">No action is recommended on the current evidence.</p> : (
          <ol className="space-y-2">{c.recommended_actions.map((a: any, i: number) => (<li key={i} className="avoid-break grid grid-cols-[64px_1fr] gap-3 text-[12.5px] leading-[19px]"><span className="font-mono text-[10px] uppercase tracking-[0.1em]" style={{ color: SEV_PRINT[a.priority] }}>{a.priority}</span><span>{a.action} <Ref>{a.based_on.length ? `[${a.based_on.join(', ')}] · ` : ''}requires human approval</Ref></span></li>))}</ol>)}

        <H2 n="10">Indicators</H2>
        <table className="w-full border-collapse"><thead><tr><th className={th}>Type</th><th className={th}>Value</th><th className={th}>Evidence</th></tr></thead>
          <tbody>{c.indicators.slice(0, 60).map((i: any) => (<tr key={`${i.type}${i.value}`}><td className={td}>{i.type}</td><td className={`${td} break-all font-mono text-[10.5px]`} style={{ color: i.in_suspicious_finding ? '#b06a12' : undefined }}>{i.value}</td><td className={`${td} font-mono text-[10px]`}>{i.evidence_ids.join(', ')}</td></tr>))}</tbody></table>
        <p className="mt-2 text-[11.5px] text-titanium-mute print:text-[#5b6675]">{Math.min(60, c.indicators.length)} of {c.indicator_total} unique indicators shown; indicators referenced by suspicious findings are listed first and highlighted. The JSON export contains the first 200.</p>

        <footer className="mt-12 border-t border-line-strong pt-3 font-mono text-[9.5px] leading-4 text-titanium-mute print:border-[#151A22] print:text-[#5b6675]">Generated by ARGUS. Findings are evidence-backed and were independently re-checked; sequences and narrative marked “inferred” are hypotheses. This report does not constitute attribution. All actions require human approval.</footer>
      </article>
    </div>
  );
}
