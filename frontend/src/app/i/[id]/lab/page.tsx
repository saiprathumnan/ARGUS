'use client';
import Link from 'next/link';
import { useMemo, useState } from 'react';
import { useApi, usePersisted } from '@/lib/api';
import type { InvDetail, Mitre, Rule, SystemInfo } from '@/lib/types';
import { Empty, ErrorState, Icon, KV, Loading, Meter, Panel, Segmented, Tag } from '@/components/ui/kit';
import { pct, utc, words } from '@/lib/format';

const TACTIC_ORDER = ['resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'command-and-control', 'exfiltration', 'impact'];

function Confusion({ m }: { m: { tn: number; fp: number; fn: number; tp: number } }) {
  const cell = (label: string, n: number, good: boolean) => (<div className={`border p-2 ${good ? 'border-cyan/40' : 'border-threat/40'}`}><div className="micro">{label}</div><div className={`font-display text-[20px] ${good ? 'text-cyan' : 'text-threat'}`}>{n.toLocaleString()}</div></div>);
  return <div className="grid max-w-xs grid-cols-2 gap-1">{cell('true negative', m.tn, true)}{cell('false positive', m.fp, false)}{cell('false negative', m.fn, false)}{cell('true positive', m.tp, true)}</div>;
}

export default function Lab({ params }: { params: { id: string } }) {
  const id = params.id;
  const inv = useApi<InvDetail>(`/investigations/${id}`, 4000);
  const stamp = inv.data ? `?s=${inv.data.status}${inv.data.counts.rules}` : '';
  const rules = useApi<Rule[]>(`/investigations/${id}/rules${stamp}`);
  const mitre = useApi<Mitre[]>(`/investigations/${id}/mitre${stamp}`);
  const sys = useApi<SystemInfo>('/system');
  const [tab, setTab] = usePersisted<'rules' | 'attack' | 'models'>(`argus.${id}.labTab`, 'rules');
  const [pick, setPick] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const rule = rules.data?.find((r) => r.id === pick) || rules.data?.[0] || null;
  const byTactic = useMemo(() => {
    const m = new Map<string, Map<string, Mitre[]>>();
    for (const x of mitre.data || []) for (const t of x.tactics) { if (!m.has(t)) m.set(t, new Map()); const tm = m.get(t)!; tm.set(x.technique_id, [...(tm.get(x.technique_id) || []), x]); }
    return [...m.entries()].sort((a, b) => TACTIC_ORDER.indexOf(a[0]) - TACTIC_ORDER.indexOf(b[0]));
  }, [mitre.data]);

  if (inv.loading && !inv.data) return <Loading label="Opening case" />;
  if (inv.error && !inv.data) return <ErrorState error={inv.error} retry={inv.reload} />;
  const notRun = inv.data?.status === 'created';
  const download = (r: Rule) => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([r.content], { type: 'text/plain' })); a.download = `${r.title.replace(/[^a-z0-9]+/gi, '_').toLowerCase()}_v${r.version}.${r.format === 'sigma' ? 'yml' : 'yar'}`; a.click(); URL.revokeObjectURL(a.href); };

  return (
    <div className="flex h-full min-h-[600px] flex-col gap-3 p-3">
      <div className="panel flex flex-wrap items-center gap-3 px-3 py-2">
        <Segmented label="Laboratory section" value={tab} onChange={setTab} options={[{ id: 'rules', label: `Detection rules ${rules.data?.length ?? ''}` }, { id: 'attack', label: `ATT&CK ${new Set((mitre.data || []).map((m) => m.technique_id)).size || ''}` }, { id: 'models', label: 'Models' }]} />
        <span className="micro ml-auto normal-case tracking-normal">Rules are generated for review. ARGUS never deploys them.</span>
      </div>

      {tab === 'rules' && (rules.loading && !rules.data ? <Loading /> : rules.error ? <ErrorState error={rules.error} retry={rules.reload} /> : !rules.data?.length ? (
        <Panel title="Detection rules" className="flex-1"><Empty icon="lab" title="No rules generated">{notRun ? 'Rules are generated from verified findings once the analysis has run.' : 'No verified finding in this case maps to a rule template (rules come from authentication, process, network and file findings).'}</Empty></Panel>
      ) : (
        <div className="grid grid-cols-[minmax(0,1fr)] min-h-0 flex-1 gap-3 lg:grid-cols-[340px_minmax(0,1fr)]">
          <Panel title="Generated rules" meta={`${rules.data.length}`} bodyClass="overflow-auto">
            <ul>{rules.data.map((r) => (
              <li key={r.id} className="border-b border-line"><button onClick={() => setPick(r.id)} aria-current={rule?.id === r.id} className={`relative block w-full px-3 py-2 text-left hover:bg-elevated ${rule?.id === r.id ? 'bg-elevated' : ''}`}>
                {rule?.id === r.id && <span className="absolute inset-y-0 left-0 w-[2px] bg-amber" />}
                <div className="flex items-center gap-2"><Tag tone={r.format === 'sigma' ? 'cyan' : 'amber'}>{r.format}</Tag><Tag>v{r.version}</Tag>{r.syntax_valid ? <Icon name="check" size={13} className="text-cyan" /> : <Icon name="alert" size={13} className="text-threat" />}</div>
                <div className="mt-1 text-body text-paper">{r.title}</div></button></li>))}</ul>
          </Panel>
          {rule && (
            <div className="grid grid-cols-[minmax(0,1fr)] min-h-0 gap-3 xl:grid-cols-2">
              <Panel title={rule.format === 'sigma' ? 'Sigma rule' : 'YARA rule'} meta={rule.id} bodyClass="overflow-auto"
                actions={<div className="flex gap-1"><button className="btn h-6" onClick={() => { navigator.clipboard?.writeText(rule.content).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }); }}>{copied ? 'Copied' : 'Copy'}</button><button className="btn h-6" onClick={() => download(rule)}>Download</button></div>}>
                <pre className="p-3 font-mono text-[11.5px] leading-[18px] text-titanium"><code>{rule.content}</code></pre>
              </Panel>
              <Panel title="Validation and testing" bodyClass="overflow-auto">
                <div className="space-y-4 p-3">
                  <div><div className="micro mb-1 text-amber">Syntax</div>
                    <div className={`flex items-center gap-2 text-body ${rule.syntax_valid ? 'text-cyan' : 'text-threat'}`}><Icon name={rule.syntax_valid ? 'check' : 'alert'} size={14} />{rule.syntax_valid ? (rule.validation.syntax || 'valid') : 'Rule failed validation'}</div>
                    {(rule.validation.issues || []).map((i: string, k: number) => <p key={k} className="mt-1 text-data text-threat">{i}</p>)}
                    {(rule.validation.unsupported_fields || []).length > 0 && <p className="mt-1 text-data text-threat">Unsupported fields for this log source: {rule.validation.unsupported_fields.join(', ')}</p>}
                    {(rule.validation.pysigma_validator_issues || []).length > 0 && <details className="mt-1"><summary className="micro cursor-pointer normal-case tracking-normal">{rule.validation.pysigma_validator_issues.length} pySigma style note(s)</summary><ul className="mt-1 space-y-0.5">{rule.validation.pysigma_validator_issues.map((i: string, k: number) => <li key={k} className="text-data text-titanium-mute">{i}</li>)}</ul></details>}
                  </div>
                  {rule.format === 'sigma' && rule.validation.test && (<>
                    <div><div className="micro mb-1 text-amber">Against the source evidence</div>
                      <div className="flex items-baseline gap-2"><span className="font-display text-[26px] text-paper">{rule.validation.test.source_evidence.matched}</span><span className="text-body text-titanium">of {rule.validation.test.source_evidence.events_cited_by_finding} events cited by the finding matched</span></div>
                      {rule.validation.test.source_evidence.events_cited_by_finding > 0 && <div className="mt-1 max-w-xs"><Meter tone="cyan" value={rule.validation.test.source_evidence.matched / rule.validation.test.source_evidence.events_cited_by_finding} /></div>}
                      {rule.validation.test.source_evidence.events_cited_by_finding === 0 && <p className="text-data text-titanium-mute">This is an indicator rule built from non-log evidence, so there are no source log events to replay it against.</p>}</div>
                    <div><div className="micro mb-1 text-amber">Against the labelled corpus</div>
                      <dl><KV k="Benign events">{rule.validation.test.labelled_corpus.benign_events}</KV>
                        <KV k="False positives"><span className={rule.validation.test.labelled_corpus.false_positives ? 'text-threat' : 'text-cyan'}>{rule.validation.test.labelled_corpus.false_positives}</span></KV>
                        <KV k="Attack events">{rule.validation.test.labelled_corpus.attack_events_matched} of {rule.validation.test.labelled_corpus.attack_events} matched</KV></dl>
                      <p className="mt-1 text-data text-titanium-mute">{rule.validation.test.labelled_corpus.note}</p><p className="mt-1 text-data text-titanium-mute">Evaluator: {rule.validation.test.evaluator}.</p></div></>)}
                  {rule.format === 'yara' && rule.validation.test && (<div><div className="micro mb-1 text-amber">Test results</div><dl><KV k="Source files">{rule.validation.test.source_files_matched} of {rule.validation.test.source_files} matched</KV><KV k="Benign files">{rule.validation.test.benign_files} scanned</KV><KV k="False positives"><span className={rule.validation.test.false_positives.length ? 'text-threat' : 'text-cyan'}>{rule.validation.test.false_positives.length ? rule.validation.test.false_positives.join(', ') : '0'}</span></KV></dl></div>)}
                  <div><div className="micro mb-1 text-amber">Provenance</div><dl>
                    <KV k="Findings">{rule.finding_ids.map((f) => <Link key={f} href={`/i/${id}?f=${f}`} className="mr-2 text-cyan hover:underline">{f}</Link>)}</KV>
                    <KV k="Evidence">{rule.evidence_ids.map((e) => <Link key={e} href={`/i/${id}/evidence?e=${e}`} className="mr-2 text-cyan hover:underline">{e}</Link>)}</KV>
                    <KV k="Version">{rule.version} · generated {utc(rule.created_at)} UTC</KV><KV k="Deployed">{rule.deployed ? 'yes' : 'no — review and deploy through your own change process'}</KV></dl></div>
                </div>
              </Panel>
            </div>)}
        </div>))}

      {tab === 'attack' && (
        <Panel title="MITRE ATT&CK mapping" meta={`${(mitre.data || []).length} evidence-linked mappings`} className="min-h-0 flex-1" bodyClass="overflow-auto">
          {mitre.loading && !mitre.data ? <Loading /> : mitre.error ? <ErrorState error={mitre.error} retry={mitre.reload} /> : !byTactic.length ? <Empty icon="shield" title="No technique mapped">{notRun ? 'Mappings are created from verified findings after analysis.' : 'No verified finding met the evidence bar for an ATT&CK technique. ARGUS does not assign techniques speculatively.'}</Empty> : (
            <div className="grid gap-px bg-line md:grid-cols-2 2xl:grid-cols-3">{byTactic.map(([tactic, techs]) => (
              <section key={tactic} className="bg-graphite p-3"><h3 className="micro text-amber">{words(tactic.replace(/-/g, '_'))}</h3>
                <ul className="mt-2 space-y-3">{[...techs.entries()].map(([tid, ms]) => (
                  <li key={tid}><a href={ms[0].reference_url} target="_blank" rel="noreferrer noopener" className="group flex items-baseline gap-2"><span className="data text-cyan group-hover:underline">{tid}</span><span className="text-body text-paper">{ms[0].technique_name}</span></a>
                    <ul className="mt-1 space-y-1 border-l border-line pl-2">{ms.map((m) => (<li key={m.id} className="text-data text-titanium">{m.rationale} <Link href={`/i/${id}?f=${m.finding_id}`} className="text-cyan hover:underline">{m.finding_id}</Link> <span className="text-titanium-mute">· conf {pct(m.confidence)}</span></li>))}</ul></li>))}</ul></section>))}</div>)}
        </Panel>)}

      {tab === 'models' && (
        <div className="grid grid-cols-[minmax(0,1fr)] min-h-0 flex-1 gap-3 overflow-auto lg:grid-cols-2">
          {sys.loading ? <Loading /> : sys.error ? <ErrorState error={sys.error} retry={sys.reload} /> : sys.data && (<>
            <Panel title="Phishing URL classifier" meta={sys.data.models.phishing_url_classifier.installed ? 'installed' : 'not installed'} bodyClass="overflow-auto">
              {!sys.data.models.phishing_url_classifier.metrics ? <Empty title="Model not trained">Run <code className="data">python -m app.ml.train_phishing --data &lt;dataset dir&gt;</code>.</Empty> : (() => { const m = sys.data.models.phishing_url_classifier.metrics; const a = m['test_metrics_threshold_0.5'], b = m['test_metrics_threshold_0.8_used_for_findings']; return (
                <div className="space-y-4 p-3">
                  <dl><KV k="Model">{m.model}</KV><KV k="Dataset" mono={false}>{m.dataset.name} — {m.dataset.rows_after_dedup.toLocaleString()} URLs after de-duplication ({m.dataset.phishing.toLocaleString()} phishing)</KV><KV k="Split" mono={false}>{m.split.method}; {m.split.test.toLocaleString()} held-out URLs from {m.split.test_domains.toLocaleString()} domains, {m.split.shared_domains} shared with training</KV></dl>
                  <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">{[['Accuracy', a.accuracy], ['Precision', a.precision], ['Recall', a.recall], ['F1', a.f1], ['ROC AUC', a.roc_auc]].map(([k, v]) => (<div key={k as string}><div className="micro">{k}</div><div className="font-display text-[22px] text-paper">{(v as number).toFixed(3)}</div></div>))}</div>
                  <div className="grid gap-4 sm:grid-cols-2"><div><div className="micro mb-1">Confusion matrix · threshold 0.5</div><Confusion m={a.confusion_matrix} /></div><div><div className="micro mb-1">Threshold 0.8 · used for findings</div><Confusion m={b.confusion_matrix} /><p className="micro mt-1 normal-case tracking-normal">precision {b.precision} · recall {b.recall}</p></div></div>
                  <div><div className="micro mb-1 text-amber">Limitations</div><ul className="list-disc space-y-1 pl-4 text-data text-titanium">{m.limitations.map((l: string, i: number) => <li key={i}>{l}</li>)}</ul></div>
                </div>); })()}
            </Panel>
            <Panel title="Network anomaly detector" meta={sys.data.models.network_anomaly.installed ? 'installed' : 'not installed'} bodyClass="overflow-auto">
              {!sys.data.models.network_anomaly.metrics ? <Empty title="Model not trained">Run <code className="data">python -m app.ml.train_anomaly</code>.</Empty> : (() => { const m = sys.data.models.network_anomaly.metrics; return (
                <div className="space-y-4 p-3">
                  <dl><KV k="Model">{m.model}</KV><KV k="Training data" mono={false}>{m.training_data} ({m.train_rows.toLocaleString()} flows)</KV><KV k="Evaluation" mono={false}>{m.evaluation_data}</KV><KV k="Threshold" mono={false}>{m.threshold_rule}</KV></dl>
                  <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">{[['Precision', m.metrics.precision], ['Recall', m.metrics.recall], ['F1', m.metrics.f1], ['ROC AUC', m.metrics.roc_auc]].map(([k, v]) => (<div key={k as string}><div className="micro">{k}</div><div className="font-display text-[22px] text-paper">{(v as number).toFixed(3)}</div></div>))}</div>
                  <div className="grid gap-4 sm:grid-cols-2"><div><div className="micro mb-1">Confusion matrix</div><Confusion m={m.metrics.confusion_matrix} /></div>
                    <div><div className="micro mb-1">Flagged by traffic profile</div><ul>{Object.entries(m.flagged_by_profile as Record<string, { n: number; flagged: number }>).map(([k, v]) => (<li key={k} className="grid grid-cols-[130px_1fr_52px] items-center gap-2 py-0.5"><span className="data text-titanium-mute">{words(k)}</span><Meter value={v.flagged / v.n} tone={['beacon', 'exfil', 'scan_probe', 'odd_port_interactive'].includes(k) ? 'threat' : 'cyan'} /><span className="data text-right">{v.flagged}/{v.n}</span></li>))}</ul><p className="micro mt-1 normal-case tracking-normal">Red rows are the injected anomaly profiles; the rest are benign.</p></div></div>
                  <div><div className="micro mb-1 text-amber">Limitations</div><ul className="list-disc space-y-1 pl-4 text-data text-titanium">{m.limitations.map((l: string, i: number) => <li key={i}>{l}</li>)}</ul></div>
                </div>); })()}
            </Panel></>)}
        </div>)}
    </div>
  );
}
