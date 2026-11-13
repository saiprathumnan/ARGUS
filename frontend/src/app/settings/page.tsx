'use client';
import { useApi } from '@/lib/api';
import type { SystemInfo } from '@/lib/types';
import { ErrorState, KV, Loading, Panel, StatusDot, Tag } from '@/components/ui/kit';
import { bytes, KIND_LABEL, utc } from '@/lib/format';

interface Audit { id: number; at: string; actor: string; action: string; target: string; detail: Record<string, any>; remote_addr: string }
const Env = ({ children }: { children: string }) => <code className="border border-line px-1 font-mono text-[11px] text-amber">{children}</code>;

export default function Settings() {
  const sys = useApi<SystemInfo>('/system', 10000);
  const audit = useApi<Audit[]>('/audit?limit=60', 10000);
  if (sys.loading && !sys.data) return <Loading label="Reading engine configuration" />;
  if (sys.error && !sys.data) return <ErrorState error={sys.error} retry={sys.reload} />;
  const s = sys.data!;
  return (
    <div className="mx-auto max-w-[1400px] space-y-3 p-3 lg:p-6">
      <div><div className="micro text-amber">Engine</div><h1 className="h-display mt-1 text-[26px]">Settings and integrations</h1>
        <p className="mt-1 max-w-[80ch] text-body text-titanium">This page reads the live backend configuration. Settings are changed through environment variables on the server and take effect on restart; secrets are never sent to the browser.</p></div>
      <div className="grid gap-3 lg:grid-cols-2">
        <Panel title="Engine">
          <dl className="p-3"><KV k="Version">{s.version}</KV><KV k="Environment">{s.environment}</KV><KV k="Database">{s.database}</KV>
            <KV k="API auth" mono={false}>{s.auth_required ? 'API key required (held by the interface server)' : <>Open (local mode). Set <Env>ARGUS_API_KEY</Env> before exposing the API.</>}</KV>
            <KV k="Upload limit">{bytes(s.limits.max_upload_bytes)} per file · {s.limits.max_evidence_per_investigation} items per case</KV><KV k="Rate limit">{s.limits.rate_limit_per_minute} requests / minute / client</KV>
            <KV k="Evidence kinds" mono={false}><div className="flex flex-wrap gap-1">{s.evidence_kinds.map((k) => <Tag key={k}>{KIND_LABEL[k] || k}</Tag>)}</div></KV></dl>
        </Panel>
        <Panel title="Network behaviour">
          <dl className="p-3">
            <KV k="Live URL fetch" mono={false}><span className="flex items-center gap-2"><StatusDot status={s.network.live_url_fetch ? 'completed' : 'created'} />{s.network.live_url_fetch ? 'Enabled, through the SSRF guard (public addresses only, DNS-pinned, redirects re-validated)' : 'Disabled. Submitted URLs are analysed as text and never requested.'}</span><div className="micro mt-1 normal-case tracking-normal"><Env>ARGUS_ALLOW_NETWORK_FETCH</Env></div></KV>
            <KV k="Language model" mono={false}><span className="flex items-center gap-2"><StatusDot status={s.llm.provider !== 'none' ? 'completed' : 'created'} />{s.llm.provider === 'none' ? 'None. Report narrative is produced by deterministic templates.' : `${s.llm.provider} · ${s.llm.model}`}</span><div className="micro mt-1 normal-case tracking-normal">Role: {s.llm.role}. <Env>ARGUS_LLM_PROVIDER</Env></div></KV>
          </dl>
        </Panel>
        <Panel title="Threat intelligence">
          <ul>{s.threat_intel.providers.map((p) => (<li key={p.name} className="flex items-center gap-3 border-b border-line px-3 py-2 last:border-0"><StatusDot status={p.enabled ? 'completed' : 'created'} /><span className="data w-32 text-paper">{p.name}</span><span className="text-data text-titanium-mute">{p.reason}</span><span className="micro ml-auto">{p.enabled ? 'active' : 'inactive'}</span></li>))}</ul>
          <p className="border-t border-line p-3 text-data text-titanium-mute">{s.threat_intel.offline_mode ? <>Offline mode: only the bundled sample bundle (fictional indicators) is consulted. Set <Env>ARGUS_INTEL_OFFLINE=false</Env> and provide <Env>ARGUS_VIRUSTOTAL_API_KEY</Env>, <Env>ARGUS_ABUSEIPDB_API_KEY</Env> or <Env>ARGUS_OTX_API_KEY</Env> to query real services.</> : 'Online mode: providers with a configured key are queried, cached and rate-limit aware.'}</p>
        </Panel>
        <Panel title="Models and reference data">
          <dl className="p-3">
            <KV k="Phishing URLs" mono={false}>{s.models.phishing_url_classifier.installed ? `Installed · held-out accuracy ${s.models.phishing_url_classifier.metrics['test_metrics_threshold_0.5'].accuracy} · trained ${utc(s.models.phishing_url_classifier.metrics.trained_at)}` : 'Not installed'}</KV>
            <KV k="Network anomaly" mono={false}>{s.models.network_anomaly.installed ? `Installed · synthetic hold-out ROC AUC ${s.models.network_anomaly.metrics.metrics.roc_auc} · trained ${utc(s.models.network_anomaly.metrics.trained_at)}` : 'Not installed'}</KV>
            <KV k="Visual references" mono={false}>{s.vision.reference_pages.length ? <ul>{s.vision.reference_pages.map((r) => <li key={r.file} className="text-data">{r.name} <span className="text-titanium-mute">· {r.legitimate_domains.join(', ')}</span></li>)}</ul> : 'No reference screenshots installed'}</KV>
          </dl>
          <p className="border-t border-line p-3 text-data text-titanium-mute">Full evaluation figures and limitations are in each case’s Detection Laboratory under Models.</p>
        </Panel>
      </div>
      <Panel title="Audit log" meta="latest 60" bodyClass="max-h-[360px] overflow-auto">
        {audit.loading && !audit.data ? <Loading /> : audit.error ? <ErrorState error={audit.error} retry={audit.reload} /> : !audit.data?.length ? <p className="p-3 text-data text-titanium-mute">No audited action has been recorded yet.</p> : (
          <table className="w-full border-collapse text-left"><thead className="sticky top-0 bg-graphite"><tr className="micro border-b border-line">{['Time (UTC)', 'Actor', 'Action', 'Target', 'Detail'].map((h) => <th key={h} className="px-3 py-1.5 font-normal">{h}</th>)}</tr></thead>
            <tbody>{audit.data.map((a) => (<tr key={a.id} className="border-b border-line"><td className="data whitespace-nowrap px-3 py-1 text-titanium-mute">{utc(a.at)}</td><td className="data px-3 py-1">{a.actor}</td><td className="data px-3 py-1 text-paper">{a.action}</td><td className="data px-3 py-1">{a.target}</td><td className="data max-w-[420px] truncate px-3 py-1 text-titanium-mute" title={JSON.stringify(a.detail)}>{Object.entries(a.detail).map(([k, v]) => `${k}=${typeof v === 'string' ? v.slice(0, 40) : v}`).join(' · ')}</td></tr>))}</tbody></table>)}
      </Panel>
    </div>
  );
}
