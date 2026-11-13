"""Persist a ParsedEvidence into the relational schema, keeping provenance links intact."""
import hashlib

from sqlalchemy.orm import Session

from ..models import Evidence, Finding, Indicator, Relationship, SecurityEvent
from .base import ParsedEvidence


def canonical(type_: str, value: str) -> str:
    v = value.strip()
    if type_ in ("domain", "email", "sha256", "host"):
        v = v.lower().rstrip(".")
    return v


def fingerprint(e) -> str:
    ts = e.timestamp.replace(microsecond=0).isoformat() if e.timestamp else ""
    raw = "|".join(str(x or "") for x in (e.category, e.action, ts, e.src_ip, e.dst_ip, e.dst_port, e.user, e.host, e.outcome, e.domain, e.url, e.data.get("command_line", "")))
    return hashlib.sha256(raw.encode()).hexdigest()


def persist(db: Session, ev: Evidence, pe: ParsedEvidence) -> dict:
    inv = ev.investigation_id
    key_to_id: dict[str, str] = {}
    for e in pe.events:
        row = SecurityEvent(investigation_id=inv, evidence_id=ev.id, timestamp=e.timestamp, category=e.category, action=e.action, outcome=e.outcome, src_ip=e.src_ip, dst_ip=e.dst_ip,
                            dst_port=e.dst_port, protocol=e.protocol, domain=e.domain, url=e.url[:2000] if e.url else None, user=e.user, host=e.host, summary=e.summary[:500],
                            data=e.data, record_ref=e.record_ref[:80], fingerprint=fingerprint(e))
        db.add(row)
        db.flush()
        if e.key:
            key_to_id[e.key] = row.id
    seen = set()
    n_ioc = 0
    for i in pe.indicators:
        v = canonical(i.type, i.value)
        if (i.type, v) in seen or not v:
            continue
        seen.add((i.type, v))
        db.add(Indicator(investigation_id=inv, evidence_id=ev.id, type=i.type, value=v, context=i.context[:300], first_seen=i.first_seen, last_seen=i.last_seen))
        n_ioc += 1
    for f in pe.findings:
        db.add(Finding(investigation_id=inv, detector=f.detector, title=f.title[:300], description=f.description, severity=f.severity, classification=f.classification, basis=f.basis,
                       confidence=float(f.confidence), evidence_ids=[ev.id], event_ids=[key_to_id[k] for k in f.event_keys if k in key_to_id][:200],
                       indicator_values=[canonical("domain", str(v)) if "." in str(v) and "/" not in str(v) and "@" not in str(v) else str(v) for v in f.indicator_values][:40],
                       details=f.details, produced_by="detection_engine"))
    for r in pe.relations:
        db.add(Relationship(investigation_id=inv, source_type=r.source[0], source_value=canonical(*r.source), target_type=r.target[0], target_value=canonical(*r.target), relation=r.relation,
                            basis=r.basis, confidence=r.confidence, evidence_ids=[ev.id], event_ids=[key_to_id[k] for k in r.event_keys if k in key_to_id][:50],
                            first_seen=r.first_seen, last_seen=r.last_seen, count=r.count, explanation=r.explanation[:500]))
    ev.meta = {**(ev.meta or {}), **pe.meta}
    ev.status = "parsed"
    db.flush()
    return {"events": len(pe.events), "indicators": n_ioc, "findings": len(pe.findings), "relations": len(pe.relations)}
