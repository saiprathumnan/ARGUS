"""Evidence correlation engine.

Principles
  * An edge exists only if a specific piece of evidence supports it; the edge stores those evidence/event ids.
  * basis = observed (seen in evidence) | derived (structural identity, e.g. URL -> its host) | inferred (heuristic).
  * Two indicators are the same entity only on exact canonical equality. Look-alike strings are never merged.
  * Cross-source chains are built only from observed/derived edges; their confidence is the product of edge
    confidences. Temporal ordering between sources is reported as an inference.
"""
from collections import defaultdict
from datetime import timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..analysis.ioc import is_private_ip, registered_domain
from ..analysis.url import normalise_url
from ..models import Evidence, Finding, Indicator, IntelRecord, Relationship, SecurityEvent

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def merge_relationships(db: Session, inv: str) -> int:
    """Collapse identical edges reported by several evidence items into one edge carrying all provenance."""
    rels = list(db.scalars(select(Relationship).where(Relationship.investigation_id == inv)))
    groups: dict[tuple, list[Relationship]] = defaultdict(list)
    for r in rels:
        groups[(r.source_type, r.source_value, r.target_type, r.target_value, r.relation)].append(r)
    removed = 0
    for items in groups.values():
        if len(items) == 1:
            continue
        keep = items[0]
        for o in items[1:]:
            keep.evidence_ids = sorted(set(keep.evidence_ids) | set(o.evidence_ids))
            keep.event_ids = list(dict.fromkeys(keep.event_ids + o.event_ids))[:100]
            keep.count += o.count
            fs = [_aware(x) for x in (keep.first_seen, o.first_seen) if x]
            ls = [_aware(x) for x in (keep.last_seen, o.last_seen) if x]
            keep.first_seen, keep.last_seen = (min(fs) if fs else None), (max(ls) if ls else None)
            keep.confidence = max(keep.confidence, o.confidence)
            if o.basis == "observed":
                keep.basis = "observed"
            db.delete(o)
            removed += 1
    db.flush()
    return removed


def mark_duplicates(db: Session, inv: str) -> int:
    seen: dict[str, str] = {}
    n = 0
    for e in db.scalars(select(SecurityEvent).where(SecurityEvent.investigation_id == inv).order_by(SecurityEvent.timestamp, SecurityEvent.id)):
        if e.category in ("network", "dns") or not e.timestamp:
            continue  # flows are already aggregates; untimed events cannot be safely deduplicated
        if e.fingerprint in seen and seen[e.fingerprint] != e.id:
            e.duplicate_of = seen[e.fingerprint]
            n += 1
        else:
            seen[e.fingerprint] = e.id
    db.flush()
    return n


def _add_finding(db, inv, **kw):
    f = Finding(investigation_id=inv, produced_by="correlation_engine", basis="correlation", **kw)
    db.add(f)
    return f


def correlate(db: Session, inv: str) -> dict:
    merged = merge_relationships(db, inv)
    dups = mark_duplicates(db, inv)
    evidence = {e.id: e for e in db.scalars(select(Evidence).where(Evidence.investigation_id == inv))}
    indicators = list(db.scalars(select(Indicator).where(Indicator.investigation_id == inv)))
    rels = list(db.scalars(select(Relationship).where(Relationship.investigation_id == inv)))
    findings = list(db.scalars(select(Finding).where(Finding.investigation_id == inv)))

    # ---- entity resolution: exact canonical equality across evidence ----
    by_entity: dict[tuple, set] = defaultdict(set)
    for i in indicators:
        by_entity[(i.type, i.value)].add(i.evidence_id)
    cross = {k: v for k, v in by_entity.items() if len(v) >= 2}
    created = []
    for (t, v), evs in sorted(cross.items()):
        kinds = sorted({evidence[e].kind for e in evs})
        if len(kinds) < 2 and t in ("user", "host"):
            continue
        related = [f for f in findings if v in f.indicator_values and f.classification in ("suspicious", "confirmed_malicious")]
        sev = "medium" if related else "low"
        created.append(_add_finding(db, inv, detector="correlation.cross_source_entity", severity=sev, classification="suspicious" if related else "insufficient_evidence",
                                    confidence=0.9, title=f"{t} {v[:80]} appears in {len(evs)} independent evidence items ({', '.join(kinds)})",
                                    description=f"The exact value '{v}' was extracted from {len(evs)} separate evidence items: " + ", ".join(f"{e} ({evidence[e].kind}: {evidence[e].original_name})" for e in sorted(evs)) +
                                                ". Matching is by exact canonical equality." + (f" {len(related)} suspicious finding(s) reference this entity." if related else ""),
                                    evidence_ids=sorted(evs), event_ids=[], indicator_values=[v], details={"entity_type": t, "evidence_kinds": kinds, "related_findings": [f.id for f in related][:20]}))
        db.add(Relationship(investigation_id=inv, source_type=t, source_value=v, target_type=t, target_value=v, relation="same_entity_across_sources", basis="observed", confidence=1.0,
                            evidence_ids=sorted(evs), explanation=f"Identical {t} value extracted from {len(evs)} evidence items."))

    # ---- chain: delivered reference (email/url/file) -> infrastructure -> observed contact (pcap/logs) ----
    out_edges: dict[tuple, list[Relationship]] = defaultdict(list)
    in_edges: dict[tuple, list[Relationship]] = defaultdict(list)
    for r in rels:
        out_edges[(r.source_type, r.source_value)].append(r)
        in_edges[(r.target_type, r.target_value)].append(r)
    delivery_kinds = {"eml", "email_headers", "url", "file", "pdf", "screenshot"}
    contact_kinds = {"pcap", "json_events", "auth_log"}
    chains = 0
    seen_chain = set()
    for r in rels:
        if r.relation != "hosted_on" or r.source_type != "url":
            continue
        url_ev = {e for e in by_entity.get(("url", r.source_value), set()) if evidence[e].kind in delivery_kinds}
        if not url_ev:
            continue
        host = (r.target_type, r.target_value)
        path_options = []  # (infra_ip_or_None, [edges], contact_edge)
        if host[0] == "ip":
            for c in in_edges[host]:
                if c.relation == "connects_to":
                    path_options.append((host[1], [r], c))
        else:
            for q in in_edges[host]:
                if q.relation == "queried" and set(q.evidence_ids) & {e for e in evidence if evidence[e].kind in contact_kinds}:
                    path_options.append((None, [r], q))
            for res in out_edges[host]:
                if res.relation in ("resolves_to", "served_by") and res.basis == "observed":
                    for c in in_edges[(res.target_type, res.target_value)]:
                        if c.relation == "connects_to":
                            path_options.append((res.target_value, [r, res], c))
        for infra_ip, edges, contact in path_options:
            contact_ev = {e for e in contact.evidence_ids if evidence[e].kind in contact_kinds}
            if not contact_ev or contact_ev & url_ev:
                continue
            key = (r.source_value, contact.source_value, infra_ip or host[1])
            if key in seen_chain:
                continue
            seen_chain.add(key)
            chains += 1
            all_edges = edges + [contact]
            conf = 1.0
            for e in all_edges:
                conf *= e.confidence
            all_ev = sorted(url_ev | {x for e in all_edges for x in e.evidence_ids})
            delivered_at = min((_aware(i.first_seen) for i in indicators if i.type == "url" and i.value == r.source_value and i.first_seen and i.evidence_id in url_ev), default=None)
            contact_at = _aware(contact.first_seen)
            order_note, sequence = "", None
            if delivered_at and contact_at:
                sequence = "contact_after_delivery" if contact_at >= delivered_at else "contact_before_delivery"
                order_note = (f" The first contact ({contact_at.isoformat()}) is {'after' if sequence == 'contact_after_delivery' else 'BEFORE'} the delivery timestamp ({delivered_at.isoformat()}); "
                              + ("the ordering is consistent with the recipient following the link, which is an inference from timestamps, not an observed click."
                                 if sequence == "contact_after_delivery" else "this ordering does not support a 'link was followed' interpretation."))
            hop_txt = f"URL {r.source_value[:100]} is hosted on {host[1]}" + (f", which the capture shows at {infra_ip}" if infra_ip and host[0] != "ip" else "")
            related = [f for f in findings if f.classification in ("suspicious", "confirmed_malicious") and ({r.source_value, host[1], infra_ip, contact.source_value} & set(f.indicator_values))]
            f = _add_finding(db, inv, detector="correlation.delivery_to_contact", severity="high" if related else "medium", classification="suspicious", confidence=round(min(conf, 0.95), 3),
                             title=f"{contact.source_value} {'looked up' if contact.relation == 'queried' else 'connected to'} infrastructure referenced by delivered content ({host[1]}" + (f" at {infra_ip})" if infra_ip and host[0] != "ip" else ")"),
                             description=f"{hop_txt}. Separately, {contact.source_value} {'queried' if contact.relation == 'queried' else 'connected to'} "
                                         f"{contact.target_value} ({contact.count} time(s)) according to {', '.join(sorted(contact_ev))}." + order_note +
                                         " Each hop is backed by the evidence listed on this finding.",
                             evidence_ids=all_ev, event_ids=list(dict.fromkeys(x for e in all_edges for x in e.event_ids))[:60],
                             indicator_values=[v for v in dict.fromkeys([r.source_value, host[1], infra_ip, contact.source_value]) if v],
                             details={"chain": [{"from": f"{e.source_type}:{e.source_value}", "relation": e.relation, "to": f"{e.target_type}:{e.target_value}", "basis": e.basis, "confidence": e.confidence,
                                                 "evidence_ids": e.evidence_ids, "relationship_id": e.id} for e in all_edges],
                                      "sequence": sequence, "sequence_basis": "inferred_from_timestamps" if sequence else None,
                                      "delivered_at": delivered_at.isoformat() if delivered_at else None, "first_contact_at": contact_at.isoformat() if contact_at else None,
                                      "supporting_findings": [x.id for x in related][:20]})
            created.append(f)

    # ---- visual similarity + serving domain ----
    for f in findings:
        if f.detector != "vision.reference_similarity":
            continue
        ev = evidence[f.evidence_ids[0]]
        src_dom = (ev.meta or {}).get("source_registered_domain")
        best = f.details.get("best_match", {})
        legit = set(best.get("legitimate_domains", []))
        if not src_dom or not legit:
            continue
        if src_dom in legit:
            created.append(_add_finding(db, inv, detector="vision.reference_served_from_official_domain", severity="info", classification="benign", confidence=0.6,
                                        title=f"Screenshot matches '{best.get('reference')}' and its stated source domain {src_dom} is an official domain",
                                        description="The analyst-asserted capture URL belongs to the reference page's legitimate domains, so the visual match is expected.",
                                        evidence_ids=[ev.id], event_ids=f.event_ids, indicator_values=[normalise_url(ev.meta["source_url"])], details={"reference": best.get("reference"), "source_domain": src_dom, "based_on_finding": f.id}))
        else:
            created.append(_add_finding(db, inv, detector="vision.lookalike_on_unrelated_domain", severity="high", classification="suspicious", confidence=round(min(0.85, best.get("combined", 0.7)), 3),
                                        title=f"Page resembling '{best.get('reference')}' was captured from unrelated domain {src_dom}",
                                        description=f"The screenshot is visually similar to the reference page '{best.get('reference')}' (similarity {best.get('combined')}), whose legitimate domains are "
                                                    f"{', '.join(sorted(legit))}. The analyst states it was captured from {ev.meta.get('source_url')}, registered domain {src_dom}. "
                                                    "This combination is a visual impersonation indicator. It depends on the analyst-asserted capture URL being accurate.",
                                        evidence_ids=[ev.id], event_ids=f.event_ids, indicator_values=[normalise_url(ev.meta["source_url"])],
                                        details={"reference": best.get("reference"), "similarity": best, "source_domain": src_dom, "based_on_finding": f.id, "depends_on": "analyst-asserted source_url"}))

    # ---- corroboration: threat intel + independently observed behaviour on the same indicator ----
    intel = [t for t in db.scalars(select(IntelRecord).where(IntelRecord.investigation_id == inv)) if t.verdict in ("malicious", "suspicious")]
    done = set()
    for t in intel:
        if t.indicator_value in done:
            continue
        behav = [f for f in findings if t.indicator_value in f.indicator_values and f.basis in ("deterministic", "signature") and f.classification in ("suspicious", "confirmed_malicious")
                 and SEV_RANK[f.severity] >= 2]
        if not behav:
            continue
        done.add(t.indicator_value)
        sample_only = all(x.source_reliability == "sample" for x in intel if x.indicator_value == t.indicator_value)
        sources = sorted({x.source for x in intel if x.indicator_value == t.indicator_value})
        created.append(_add_finding(db, inv, detector="correlation.corroborated_indicator", severity="high" if sample_only else "critical",
                                    classification="suspicious" if sample_only else "confirmed_malicious", confidence=0.8 if sample_only else 0.92,
                                    title=f"{t.indicator_type} {t.indicator_value} is flagged by threat intelligence AND shows suspicious behaviour in evidence",
                                    description=f"Reputation source(s) {', '.join(sources)} list {t.indicator_value} as {t.verdict}, and {len(behav)} independent deterministic finding(s) in the collected evidence involve the same indicator: "
                                                + "; ".join(b.title[:90] for b in behav[:3]) + "." +
                                                (" The intelligence here is bundled SAMPLE data, so ARGUS keeps this at 'suspicious' rather than confirmed." if sample_only else
                                                 " Two independent bases (external reputation and observed behaviour) agree, which meets ARGUS's bar for confirmed malicious."),
                                    evidence_ids=sorted({e for b in behav for e in b.evidence_ids}), event_ids=list(dict.fromkeys(e for b in behav for e in b.event_ids))[:60],
                                    indicator_values=[t.indicator_value], details={"intel_sources": sources, "intel_verdict": t.verdict, "behavioural_findings": [b.id for b in behav], "sample_intel_only": sample_only}))
    db.flush()
    return {"relationships_merged": merged, "duplicate_events": dups, "cross_source_entities": len(cross), "chains": chains, "findings_created": len(created),
            "relationships_total": len(rels) - 0, "entities_total": len(by_entity)}


def build_graph(db: Session, inv: str) -> dict:
    """Graph for the Evidence Universe. Nodes = evidence items + resolved entities. Nothing is synthesised."""
    evidence = list(db.scalars(select(Evidence).where(Evidence.investigation_id == inv)))
    indicators = list(db.scalars(select(Indicator).where(Indicator.investigation_id == inv)))
    rels = list(db.scalars(select(Relationship).where(Relationship.investigation_id == inv)))
    findings = [f for f in db.scalars(select(Finding).where(Finding.investigation_id == inv)) if f.verification_status != "rejected"]
    intel = list(db.scalars(select(IntelRecord).where(IntelRecord.investigation_id == inv)))
    sev: dict[str, str] = {}
    fcount: dict[str, list] = defaultdict(list)
    for f in findings:
        if f.classification in ("benign", "insufficient_evidence") and f.severity in ("info", "low"):
            weight = "info"
        else:
            weight = f.severity
        for v in f.indicator_values:
            fcount[v].append(f.id)
            if v not in sev or SEV_RANK[weight] > SEV_RANK[sev[v]]:
                sev[v] = weight
    nodes: dict[str, dict] = {}
    for e in evidence:
        nodes[f"evidence:{e.id}"] = {"id": f"evidence:{e.id}", "type": "evidence", "label": e.original_name[:60], "value": e.id, "kind": e.kind, "severity": "info",
                                     "first_seen": _aware(e.ingested_at).isoformat(), "last_seen": _aware(e.ingested_at).isoformat(), "evidence_ids": [e.id], "finding_ids": [], "sources": 1}
    for i in indicators:
        nid = f"{i.type}:{i.value}"
        n = nodes.setdefault(nid, {"id": nid, "type": i.type, "label": i.value[:60], "value": i.value, "severity": sev.get(i.value, "info"), "first_seen": None, "last_seen": None,
                                   "evidence_ids": [], "finding_ids": fcount.get(i.value, [])[:30], "contexts": [], "internal": i.type == "ip" and is_private_ip(i.value),
                                   "registered_domain": registered_domain(i.value) if i.type == "domain" else None,
                                   "intel": [{"source": t.source, "verdict": t.verdict, "reliability": t.source_reliability} for t in intel if t.indicator_value == i.value]})
        if i.evidence_id not in n["evidence_ids"]:
            n["evidence_ids"].append(i.evidence_id)
            n["contexts"].append({"evidence_id": i.evidence_id, "context": i.context})
        for attr, pick in (("first_seen", min), ("last_seen", max)):
            v = getattr(i, attr)
            if v:
                v = _aware(v).isoformat()
                n[attr] = v if n[attr] is None else pick(n[attr], v)
    for n in nodes.values():
        n["sources"] = len(n["evidence_ids"])
    edges = []
    for i in indicators:
        edges.append({"id": f"c:{i.id}", "source": f"evidence:{i.evidence_id}", "target": f"{i.type}:{i.value}", "relation": "contains", "basis": "observed", "confidence": 1.0,
                      "evidence_ids": [i.evidence_id], "explanation": f"Extracted from evidence: {i.context}", "count": 1,
                      "first_seen": _aware(i.first_seen).isoformat() if i.first_seen else None, "last_seen": _aware(i.last_seen).isoformat() if i.last_seen else None})
    for r in rels:
        s, t = f"{r.source_type}:{r.source_value}", f"{r.target_type}:{r.target_value}"
        if s == t or s not in nodes or t not in nodes:
            continue
        edges.append({"id": r.id, "source": s, "target": t, "relation": r.relation, "basis": r.basis, "confidence": r.confidence, "evidence_ids": r.evidence_ids, "event_ids": r.event_ids[:20],
                      "explanation": r.explanation, "count": r.count, "first_seen": _aware(r.first_seen).isoformat() if r.first_seen else None, "last_seen": _aware(r.last_seen).isoformat() if r.last_seen else None})
    # evidence nodes carry ingestion time (an analyst action), so they do not stretch the incident time range
    times = [n[k] for n in nodes.values() if n["type"] != "evidence" for k in ("first_seen", "last_seen") if n.get(k)]
    return {"nodes": list(nodes.values()), "edges": edges, "time_range": {"start": min(times) if times else None, "end": max(times) if times else None},
            "counts": {"nodes": len(nodes), "edges": len(edges), "by_type": {t: sum(1 for n in nodes.values() if n["type"] == t) for t in sorted({n["type"] for n in nodes.values()})}}}
