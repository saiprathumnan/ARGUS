import type { Severity, Stage } from './types';

export const SEV_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
export const SEV_HEX: Record<Severity, string> = { info: '#7C8796', low: '#52D9E8', medium: '#FF9D35', high: '#E84B55', critical: '#E84B55' };
export const sevText: Record<Severity, string> = { info: 'text-titanium-mute', low: 'text-cyan', medium: 'text-amber', high: 'text-threat', critical: 'text-threat' };
export const sevBorder: Record<Severity, string> = { info: 'border-titanium-faint', low: 'border-cyan', medium: 'border-amber', high: 'border-threat', critical: 'border-threat' };
export const VERDICT: Record<string, { label: string; tone: string; hex: string }> = {
  malicious: { label: 'Confirmed malicious', tone: 'text-threat border-threat', hex: '#E84B55' },
  suspicious: { label: 'Suspicious', tone: 'text-amber border-amber', hex: '#FF9D35' },
  benign: { label: 'No malicious indication', tone: 'text-cyan border-cyan', hex: '#52D9E8' },
  insufficient_evidence: { label: 'Insufficient evidence', tone: 'text-titanium border-titanium-mute', hex: '#B9C2CE' },
};
export const STAGES: { id: Stage; label: string }[] = [
  { id: 'evidence_collection', label: 'Evidence collection' }, { id: 'processing', label: 'Processing' }, { id: 'correlation', label: 'Correlation' },
  { id: 'verification', label: 'Verification' }, { id: 'completed', label: 'Completed' },
];
export const AGENT_LABEL: Record<string, string> = {
  orchestrator: 'Orchestrator', evidence_analyst: 'Evidence Analyst', network_analyst: 'Network Analyst', threat_intel_analyst: 'Threat Intel Analyst',
  forensics_analyst: 'Forensics Analyst', investigation_verifier: 'Verifier', report_generator: 'Report Generator', detection_engine: 'Detection Engine', correlation_engine: 'Correlation Engine',
};
export const TYPE_LABEL: Record<string, string> = { evidence: 'Evidence', ip: 'IP address', domain: 'Domain', url: 'URL', email: 'Email address', sha256: 'File hash', user: 'Account', host: 'Host' };
export const KIND_LABEL: Record<string, string> = { url: 'URL', eml: 'Email (.eml)', email_headers: 'Email headers', json_events: 'JSON events', auth_log: 'Auth log', pcap: 'Packet capture', file: 'File', pdf: 'PDF', screenshot: 'Screenshot' };

export const utc = (iso: string | null | undefined, withDate = true) => {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const s = d.toISOString();
  return withDate ? `${s.slice(0, 10)} ${s.slice(11, 19)}` : s.slice(11, 19);
};
export const bytes = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
export const pct = (n: number | null | undefined) => (n == null ? '—' : `${Math.round(n * 100)}%`);
export const words = (s: string) => s.replace(/_/g, ' ');
export const short = (s: string, n = 44) => (s.length > n ? `${s.slice(0, Math.floor(n * 0.6))}…${s.slice(-Math.floor(n * 0.3))}` : s);
