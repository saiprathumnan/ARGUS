export type Stage = 'idle' | 'evidence_collection' | 'processing' | 'correlation' | 'verification' | 'completed' | 'failed';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Verdict = 'malicious' | 'suspicious' | 'benign' | 'insufficient_evidence' | null;

export interface InvSummary {
  id: string; title: string; description: string; status: 'created' | 'running' | 'completed' | 'failed'; stage: Stage; verdict: Verdict;
  verdict_confidence: number | null; error: string | null; created_at: string; started_at: string | null; completed_at: string | null;
  counts: { evidence: number; indicators: number; events: number; findings: number; relationships: number; rules: number };
}
export interface EvidenceItem { id: string; kind: string; name: string; sha256: string; size_bytes: number; mime_type: string; source: string; submitted_by: string; ingested_at: string; status: string; parse_error: string | null; meta?: Record<string, any> }
export interface AgentRun { id: string; agent: string; task: string; status: string; attempt: number; error: string | null; started_at: string | null; finished_at: string | null }
export interface InvDetail extends InvSummary { evidence: EvidenceItem[]; agents: AgentRun[]; finding_stats: { by_severity: Record<string, number>; by_classification: Record<string, number>; by_verification: Record<string, number> } }
export interface PipelineEvent { id: number; at: string; stage: Stage; actor: string; level: 'info' | 'warn' | 'error'; message: string; data: Record<string, any> }
export interface Finding {
  id: string; detector: string; title: string; description: string; severity: Severity; classification: string; basis: string; confidence: number;
  evidence_ids: string[]; event_ids: string[]; indicators: string[]; details: Record<string, any>; produced_by: string; verification_status: string; verification_notes: string; created_at?: string;
}
export interface GraphNode {
  id: string; type: string; label: string; value: string; kind?: string; severity: Severity; first_seen: string | null; last_seen: string | null;
  evidence_ids: string[]; finding_ids: string[]; sources: number; internal?: boolean; contexts?: { evidence_id: string; context: string }[];
  intel?: { source: string; verdict: string; reliability: string }[];
}
export interface GraphEdge { id: string; source: string; target: string; relation: string; basis: 'observed' | 'derived' | 'inferred'; confidence: number; evidence_ids: string[]; explanation: string; count: number; first_seen: string | null; last_seen: string | null }
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[]; time_range: { start: string | null; end: string | null }; counts: { nodes: number; edges: number; by_type: Record<string, number> } }
export interface TimelineEntry { id: string; at: string; layer: string; action: string; summary: string; outcome: string | null; time_basis: 'confirmed' | 'inferred' | 'submission_time'; time_basis_label: string; evidence_id: string; record_ref: string; severity: Severity; finding_ids: string[]; entities: string[] }
export interface Timeline { entries: TimelineEntry[]; total_events: number; omitted_submission_events?: number; layers: string[]; range: { start: string; end: string } | null; attack_sequence: null | { label: string; basis: string; steps: { phase: string; at: string | null; finding_id: string; title: string; evidence_ids: string[] }[]; phases_in_expected_order: boolean }; inconsistencies: { evidence_id: string; issue: string }[] }
export interface Rule { id: string; rule_key: string; version: number; format: 'sigma' | 'yara'; title: string; content: string; finding_ids: string[]; evidence_ids: string[]; syntax_valid: boolean; validation: Record<string, any>; deployed: boolean; created_at: string }
export interface Mitre { id: string; technique_id: string; technique_name: string; tactics: string[]; rationale: string; reference_url: string; confidence: number; finding_id: string }
export interface IndicatorRow { type: string; value: string; evidence_ids: string[]; contexts: string[]; first_seen: string | null; finding_ids: string[]; max_severity: Severity; intel: { source: string; verdict: string; reliability: string; summary: string; reference: string; queried_at: string }[] }
export interface Report { id: string; version: number; created_at: string; narrative_source: string; content: Record<string, any> }
export interface SystemInfo { version: string; environment: string; auth_required: boolean; database: string; limits: Record<string, number>; evidence_kinds: string[]; network: Record<string, boolean>; threat_intel: { offline_mode: boolean; providers: { name: string; enabled: boolean; reason: string }[] }; llm: { provider: string; model: string | null; role: string }; models: Record<string, { installed: boolean; metrics: any }>; vision: { reference_pages: { name: string; file: string; legitimate_domains: string[] }[] }; totals: Record<string, number> }
export interface Scenario { id: string; title: string; description: string; expected_verdict: string; evidence: { kind: string; file?: string; url?: string }[] }
