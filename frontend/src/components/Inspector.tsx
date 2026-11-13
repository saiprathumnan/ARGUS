'use client';
import Link from 'next/link';
import type { Finding, Graph, GraphNode } from '@/lib/types';
import type { Indexed } from '@/lib/graph';
import { Classification, Icon, KV, Meter, SeverityTag, Tag } from '@/components/ui/kit';
import { AGENT_LABEL, pct, short, TYPE_LABEL, utc, words } from '@/lib/format';

export function FindingCard({ f, caseId, onEvidence, dense }: { f: Finding; caseId: string; onEvidence?: (id: string) => void; dense?: boolean }) {
  const rejected = f.verification_status === 'rejected';
  return (
    <article className={`border-l-2 py-2 pl-3 pr-2 ${rejected ? 'border-titanium-faint opacity-60' : f.severity === 'high' || f.severity === 'critical' ? 'border-threat' : f.severity === 'medium' ? 'border-amber' : f.severity === 'low' ? 'border-cyan' : 'border-titanium-faint'}`}>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <SeverityTag severity={f.severity} /><Classification value={f.classification} />
        <span className="micro">basis · {words(f.basis)}</span><span className="micro">conf · {pct(f.confidence)}</span>
      </div>
      <h3 className={`mt-1 text-body font-medium text-paper ${rejected ? 'line-through' : ''}`}>{f.title}</h3>
      {!dense && <p className="mt-1 text-body text-titanium">{f.description}</p>}
      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="micro normal-case tracking-normal">{f.id}</span>
        {f.evidence_ids.map((e) => onEvidence
          ? <button key={e} onClick={() => onEvidence(e)} className="micro normal-case tracking-normal text-cyan hover:underline">{e}</button>
          : <Link key={e} href={`/i/${caseId}/evidence?e=${e}`} className="micro normal-case tracking-normal text-cyan hover:underline">{e}</Link>)}
        <span className="micro normal-case tracking-normal">by {AGENT_LABEL[f.produced_by] || f.produced_by}</span>
      </div>
      {!dense && (
        <div className={`mt-1.5 flex items-start gap-1.5 text-data ${rejected ? 'text-threat' : f.verification_status === 'downgraded' ? 'text-amber' : 'text-titanium-mute'}`}>
          <Icon name={rejected ? 'close' : 'check'} size={12} className="mt-[3px] shrink-0" />
          <span><span className="uppercase">{f.verification_status}</span> — {f.verification_notes || 'awaiting verification'}</span>
        </div>
      )}
    </article>
  );
}

export function EntityInspector({ node, graph, ix, findings, caseId, onSelect, onIsolate, isolated, onExpand, expanded }: {
  node: GraphNode; graph: Graph; ix: Indexed; findings: Finding[]; caseId: string; onSelect: (id: string) => void; onIsolate?: () => void; isolated?: boolean; onExpand?: () => void; expanded?: boolean;
}) {
  const links = ix.adj.get(node.id) || [];
  const related = findings.filter((f) => node.finding_ids.includes(f.id) || (node.type === 'evidence' && f.evidence_ids.includes(node.value)));
  const cluster = node.type === 'evidence' ? ix.clusterSize.get(node.id) || 0 : 0;
  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line p-3">
        <div className="flex items-center gap-2"><Tag>{TYPE_LABEL[node.type] || node.type}</Tag><SeverityTag severity={node.severity} />{node.internal && <Tag>internal</Tag>}{node.sources > 1 && <Tag tone="amber">{node.sources} sources</Tag>}</div>
        <div className="data mt-2 break-all text-paper">{node.value}</div>
        <div className="mt-2 flex flex-wrap gap-2">
          {onIsolate && <button className="btn h-7" onClick={onIsolate} aria-pressed={isolated}><Icon name="focus" size={13} />{isolated ? 'Show all' : 'Isolate'}</button>}
          {onExpand && cluster > 0 && graph.nodes.length > 60 && <button className="btn h-7" onClick={onExpand} aria-pressed={expanded}><Icon name="layers" size={13} />{expanded ? 'Collapse' : `Expand ${cluster}`}</button>}
          {node.type === 'evidence' && <Link className="btn h-7" href={`/i/${caseId}/evidence?e=${node.value}`}><Icon name="evidence" size={13} />Open evidence</Link>}
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <dl className="px-3 py-1">
          <KV k="First seen">{utc(node.first_seen)}</KV>
          <KV k="Last seen">{utc(node.last_seen)}</KV>
          {node.type !== 'evidence' && <KV k="Found in" mono={false}>
            <ul className="space-y-1">{(node.contexts || []).map((c, i) => (<li key={i}><Link href={`/i/${caseId}/evidence?e=${c.evidence_id}`} className="data text-cyan hover:underline">{c.evidence_id}</Link><span className="text-data text-titanium-mute"> — {c.context}</span></li>))}</ul>
          </KV>}
          {!!node.intel?.length && <KV k="Reputation" mono={false}><ul className="space-y-1">{node.intel.map((t, i) => (<li key={i} className="text-data"><span className={t.verdict === 'malicious' ? 'text-threat' : t.verdict === 'clean' ? 'text-cyan' : 'text-amber'}>{t.verdict}</span><span className="text-titanium-mute"> · {t.source} ({t.reliability}) · third-party opinion, not evidence</span></li>))}</ul></KV>}
        </dl>
        <div className="micro flex items-center gap-2 border-t border-line px-3 py-2"><span>Connected entities · {links.length}</span><div className="ticks flex-1 opacity-50" /></div>
        <ul>
          {links.slice(0, 60).map(({ edge, other }) => {
            const o = ix.byId.get(other); if (!o) return null;
            const out = edge.source === node.id;
            return (
              <li key={edge.id} className="border-b border-line">
                <button onClick={() => onSelect(other)} className="block w-full px-3 py-1.5 text-left hover:bg-elevated">
                  <div className="flex items-center gap-2">
                    <span className="micro shrink-0 text-amber">{out ? '→' : '←'} {words(edge.relation)}</span>
                    <span className="data min-w-0 flex-1 truncate">{short(o.label, 40)}</span>
                    <span className={`micro shrink-0 ${edge.basis === 'inferred' ? 'text-amber' : ''}`}>{edge.basis}</span>
                  </div>
                  <div className="mt-0.5 text-data text-titanium-mute">{edge.explanation} <span className="text-titanium-faint">[{edge.evidence_ids.join(', ')}]</span></div>
                  <div className="mt-1 flex items-center gap-2"><div className="w-16"><Meter value={edge.confidence} tone="cyan" /></div><span className="micro">conf {pct(edge.confidence)}{edge.count > 1 ? ` · ×${edge.count}` : ''}</span></div>
                </button>
              </li>
            );
          })}
          {links.length > 60 && <li className="micro px-3 py-2 normal-case tracking-normal">{links.length - 60} more connections not listed.</li>}
        </ul>
        {related.length > 0 && (<>
          <div className="micro flex items-center gap-2 px-3 py-2"><span>Findings · {related.length}</span><div className="ticks flex-1 opacity-50" /></div>
          <div className="space-y-2 px-3 pb-3">{related.slice(0, 12).map((f) => <FindingCard key={f.id} f={f} caseId={caseId} dense />)}</div>
        </>)}
      </div>
    </div>
  );
}
