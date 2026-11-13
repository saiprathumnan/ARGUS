"""The specialised investigation agents. Each has one responsibility, takes structured input from the
database and returns a structured (JSON-serialisable) output that is stored in agent_executions.
None of them can create a finding without evidence ids; the Verifier re-checks all of them afterwards."""
import hashlib
from collections import Counter, defaultdict
from datetime import timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..analysis.ioc import is_private_ip
from ..correlation.engine import SEV_RANK, correlate
from ..ingestion import pipelines  # noqa: F401  (registers pipelines)
from ..ingestion.base import PIPELINES, IngestContext
from ..ingestion.store import persist
from ..intel.service import enrich
from ..models import Evidence, Finding, Indicator, IntelRecord, SecurityEvent, utc_iso
from ..security.uploads import read_original

PHASES = [("delivery", ("email.", "url.", "ml.phishing_url", "vision.")), ("credential_access", ("auth.",)), ("execution", ("process.", "file.")),
          ("command_and_control", ("network.beaconing", "network.suspicious_port", "network.dns_tunneling_pattern", "correlation.delivery_to_contact", "ml.network_anomaly")),
          ("discovery", ("network.port_scan",)), ("exfiltration", ("network.large_outbound_transfer",)), ("defense_evasion", ("log.",))]


def _aw(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def plan(db: Session, inv: str) -> dict:
    """ORCHESTRATOR planning: decide which agents are needed from the evidence actually submitted."""
    kinds = Counter(e.kind for e in db.scalars(select(Evidence).where(Evidence.investigation_id == inv)))
    has_net = bool(kinds.get("pcap") or kinds.get("json_events"))
    tasks = [
        {"agent": "evidence_analyst", "task": f"parse and analyse {sum(kinds.values())} evidence item(s): " + ", ".join(f"{n} {k}" for k, n in kinds.items()), "required": True},
        {"agent": "network_analyst", "task": "analyse network events, communication patterns and connection sequences", "required": False,
         "skip_reason": None if has_net else "no network capture or event log was submitted"},
        {"agent": "threat_intel_analyst", "task": "enrich extracted indicators with reputation data and record sources", "required": False},
        {"agent": "forensics_analyst", "task": "correlate evidence across sources, build the timeline, propose attack sequences, list inconsistencies", "required": True},
        {"agent": "investigation_verifier", "task": "independently re-check every finding against the preserved evidence", "required": True},
        {"agent": "forensics_analyst", "task": "map verified findings to MITRE ATT&CK", "required": False},
        {"agent": "orchestrator", "task": "generate and validate detection rules from verified findings", "required": False},
        {"agent": "report_generator", "task": "assemble the forensic report from verified findings", "required": True},
    ]
    return {"evidence_kinds": dict(kinds), "tasks": tasks}


def evidence_analyst(db: Session, inv: str, emit) -> dict:
    out = {"evidence": [], "indicator_counts": {}, "missing_evidence": [], "failed": 0}
    items = list(db.scalars(select(Evidence).where(Evidence.investigation_id == inv).order_by(Evidence.ingested_at)))
    for ev in items:
        if ev.status == "parsed":
            continue
        try:
            data = read_original(ev.storage_path)
            if hashlib.sha256(data).hexdigest() != ev.sha256:
                raise ValueError("stored evidence does not match its recorded SHA-256")
            fn = PIPELINES.get(ev.kind)
            if fn is None:
                raise ValueError(f"no ingestion pipeline for kind '{ev.kind}'")
            emit("evidence_collection", "evidence_analyst", f"Parsing {ev.kind} evidence {ev.id} ({ev.original_name})", evidence_id=ev.id)
            pe = fn(data, IngestContext(ev.id, inv, ev.original_name, _aw(ev.ingested_at), {**(ev.meta or {}), "mime": ev.mime_type}))
            counts = persist(db, ev, pe)
            db.commit()
            out["evidence"].append({"evidence_id": ev.id, "kind": ev.kind, "status": "parsed", **counts})
            emit("evidence_collection", "evidence_analyst", f"{ev.id}: {counts['indicators']} indicators, {counts['events']} events, {counts['findings']} detections", evidence_id=ev.id, **counts)
        except Exception as e:
            db.rollback()
            ev = db.get(Evidence, ev.id)
            ev.status, ev.parse_error = "failed", f"{type(e).__name__}: {e}"[:500]
            db.commit()
            out["failed"] += 1
            out["evidence"].append({"evidence_id": ev.id, "kind": ev.kind, "status": "failed", "error": ev.parse_error})
            emit("evidence_collection", "evidence_analyst", f"{ev.id} could not be parsed: {ev.parse_error[:160]}", level="error", evidence_id=ev.id)
    kinds = {e.kind for e in items if e.status == "parsed"}
    out["indicator_counts"] = dict(Counter(i.type for i in db.scalars(select(Indicator).where(Indicator.investigation_id == inv))))
    findings = list(db.scalars(select(Finding).where(Finding.investigation_id == inv)))
    out["detections_by_severity"] = dict(Counter(f.severity for f in findings))
    gaps = []
    if kinds & {"eml", "email_headers", "url"} and not kinds & {"pcap", "json_events"}:
        gaps.append("No network capture or proxy/DNS log was submitted, so ARGUS cannot tell whether any host actually contacted the URLs or domains found.")
    if "pcap" in kinds and not kinds & {"json_events", "auth_log"}:
        gaps.append("No endpoint or authentication logs were submitted, so network activity cannot be tied to a process or user.")
    if kinds & {"json_events", "auth_log"} and "pcap" not in kinds and any(f.detector.startswith("process.") for f in findings):
        gaps.append("No network capture was submitted, so downloads or callbacks referenced in command lines cannot be confirmed on the wire.")
    if any(f.detector == "email.no_auth_results" for f in findings):
        gaps.append("The email carries no Authentication-Results header; obtain the copy from the receiving mail gateway to assess SPF/DKIM/DMARC.")
    if any(e.kind == "screenshot" and not (e.meta or {}).get("source_url") for e in items):
        gaps.append("A screenshot was submitted without its capture URL; visual similarity cannot be interpreted without knowing where the page was served from.")
    if "eml" in kinds and any(f.detector.startswith("email.attachment") for f in findings) and not kinds & {"file", "pdf"}:
        gaps.append("An email attachment was hashed but not submitted as a separate file; submit it for static analysis and YARA scanning.")
    out["missing_evidence"] = gaps
    return out


def network_analyst(db: Session, inv: str, emit) -> dict:
    events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.investigation_id == inv, SecurityEvent.category.in_(["network", "dns"]))))
    if not events:
        return {"skipped": True, "reason": "no network or DNS events were extracted from the evidence"}
    flows = [e for e in events if e.category == "network"]
    talk = Counter()
    ext: dict[str, dict] = defaultdict(lambda: {"connections": 0, "bytes_out": 0, "bytes_in": 0, "clients": set(), "ports": set(), "first": None, "event_ids": []})
    for e in flows:
        d = e.data or {}
        talk[e.src_ip] += d.get("packets", 1)
        if e.dst_ip and not is_private_ip(e.dst_ip):
            x = ext[e.dst_ip]
            x["connections"] += d.get("connections", 1)
            x["bytes_out"] += d.get("bytes_out", 0)
            x["bytes_in"] += d.get("bytes_in", 0)
            x["clients"].add(e.src_ip)
            x["ports"].add(e.dst_port)
            x["event_ids"].append(e.id)
            ts = _aw(e.timestamp)
            x["first"] = ts if x["first"] is None or (ts and ts < x["first"]) else x["first"]
    net_findings = [f for f in db.scalars(select(Finding).where(Finding.investigation_id == inv)) if f.detector.startswith(("network.", "ml.network_anomaly"))]
    flagged_dsts = {v for f in net_findings for v in f.indicator_values}
    sequences = []
    for dst in sorted(d for d in ext if d in flagged_dsts):
        evs = sorted((e for e in flows if e.dst_ip == dst), key=lambda e: _aw(e.timestamp) or _aw(e.timestamp))
        dns_before = [e for e in events if e.category == "dns" and dst in ((e.data or {}).get("answers") or [])]
        steps = [{"at": _aw(e.timestamp).isoformat() if e.timestamp else None, "event_id": e.id, "step": f"{e.src_ip} resolved {e.domain} to {dst}", "basis": "observed"} for e in dns_before[:3]]
        steps += [{"at": _aw(e.timestamp).isoformat() if e.timestamp else None, "event_id": e.id, "step": e.summary, "basis": "observed"} for e in evs[:6]]
        sequences.append({"destination": dst, "steps": sorted(steps, key=lambda s: s["at"] or "")})
    out = {"flows": len(flows), "dns_queries": len(events) - len(flows), "top_talkers": [{"ip": ip, "packets": n} for ip, n in talk.most_common(5)],
           "external_destinations": [{"ip": ip, "connections": v["connections"], "bytes_out": v["bytes_out"], "bytes_in": v["bytes_in"], "clients": sorted(v["clients"]),
                                      "ports": sorted(p for p in v["ports"] if p), "first_seen": v["first"].isoformat() if v["first"] else None, "event_ids": v["event_ids"][:10]}
                                     for ip, v in sorted(ext.items(), key=lambda kv: -kv[1]["connections"])[:15]],
           "unusual_traffic": [{"finding_id": f.id, "detector": f.detector, "title": f.title, "basis": f.basis} for f in net_findings],
           "connection_sequences": sequences}
    emit("processing", "network_analyst", f"{len(flows)} flows, {len(ext)} external destinations, {len(net_findings)} network detections reviewed")
    return out


def threat_intel_analyst(db: Session, inv: str, emit, only: list[tuple[str, str]] | None = None, stage: str = "processing") -> dict:
    if only is None:
        findings = list(db.scalars(select(Finding).where(Finding.investigation_id == inv)))
        hot = {v for f in findings if f.classification in ("suspicious", "confirmed_malicious") for v in f.indicator_values}
        inds = list(db.scalars(select(Indicator).where(Indicator.investigation_id == inv, Indicator.type.in_(["ip", "domain", "url", "sha256"]))))
        uniq = list(dict.fromkeys((i.type, i.value) for i in sorted(inds, key=lambda i: i.value not in hot)))[:150]
    else:
        uniq = only
    before = {t.id for t in db.scalars(select(IntelRecord).where(IntelRecord.investigation_id == inv))}
    stats = enrich(db, inv, uniq)
    new = [t for t in db.scalars(select(IntelRecord).where(IntelRecord.investigation_id == inv)) if t.id not in before]
    ev_for = defaultdict(set)
    for i in db.scalars(select(Indicator).where(Indicator.investigation_id == inv)):
        ev_for[i.value].add(i.evidence_id)
    created = 0
    for t in new:
        if t.verdict in ("malicious", "suspicious"):
            db.add(Finding(investigation_id=inv, detector="intel.reputation_hit", produced_by="threat_intel_analyst", basis="threat_intel", classification="unverified_intel",
                           severity="medium" if t.verdict == "malicious" else "low", confidence=0.3 if t.source_reliability == "sample" else 0.55,
                           title=f"{t.source} lists {t.indicator_type} {t.indicator_value[:80]} as {t.verdict}",
                           description=f"{t.summary} (source: {t.source}, reliability: {t.source_reliability}, queried {utc_iso(t.queried_at)}{', served from cache' if t.from_cache else ''}). "
                                       "Reputation data is third-party opinion, not evidence from this investigation." + (" This source is bundled SAMPLE data." if t.source_reliability == "sample" else ""),
                           evidence_ids=sorted(ev_for[t.indicator_value]), event_ids=[], indicator_values=[t.indicator_value],
                           details={"intel_record_id": t.id, "source": t.source, "reliability": t.source_reliability, "verdict": t.verdict, "reference": t.reference}))
            created += 1
    db.flush()
    emit(stage, "threat_intel_analyst", f"Looked up {len(uniq)} indicator(s) across {', '.join(stats['providers'])}: {stats['records']} record(s), {created} reputation hit(s)")
    return {**stats, "indicators_considered": len(uniq), "looked_up": [list(u) for u in uniq], "reputation_hits": created,
            "references": [{"indicator": t.indicator_value, "source": t.source, "reliability": t.source_reliability, "verdict": t.verdict, "reference": t.reference} for t in new][:60]}


def build_timeline(db: Session, inv: str) -> dict:
    evidence = {e.id: e for e in db.scalars(select(Evidence).where(Evidence.investigation_id == inv))}
    events = [e for e in db.scalars(select(SecurityEvent).where(SecurityEvent.investigation_id == inv)) if e.timestamp and not e.duplicate_of]
    findings = [f for f in db.scalars(select(Finding).where(Finding.investigation_id == inv)) if f.verification_status != "rejected"]
    f_by_event = defaultdict(list)
    for f in findings:
        for eid in f.event_ids:
            f_by_event[eid].append(f)
    entries = []
    for e in sorted(events, key=lambda e: (_aw(e.timestamp), e.id)):
        ev = evidence[e.evidence_id]
        fs = f_by_event.get(e.id, [])
        if e.action in ("url_submitted", "file_submitted", "screenshot_submitted"):
            basis, label = "submission_time", "analyst action (submission time, not incident time)"
        elif ev.kind == "auth_log" and (ev.meta or {}).get("assumed_year") and e.timestamp.year == ev.meta["assumed_year"] and (e.data or {}).get("raw", "")[:1].isalpha():
            basis, label = "inferred", "timestamp year assumed (syslog format has no year)"
        else:
            basis, label = "confirmed", "timestamp recorded in the evidence"
        sev = max((f.severity for f in fs if f.classification in ("suspicious", "confirmed_malicious")), key=lambda s: SEV_RANK[s], default="info")
        entries.append({"id": e.id, "at": _aw(e.timestamp).isoformat(), "layer": e.category, "action": e.action, "summary": e.summary, "outcome": e.outcome, "time_basis": basis, "time_basis_label": label,
                        "evidence_id": e.evidence_id, "record_ref": e.record_ref, "severity": sev, "finding_ids": [f.id for f in fs][:10],
                        "entities": [x for x in dict.fromkeys([e.src_ip, e.dst_ip, e.domain, e.url, e.user, e.host]) if x]})
    # Submission events record when the analyst handed evidence to ARGUS, not when anything happened. They are kept
    # only when they are all there is; otherwise they would stretch the incident axis to the day of analysis.
    omitted = 0
    if any(x["time_basis"] != "submission_time" for x in entries):
        omitted = sum(1 for x in entries if x["time_basis"] == "submission_time")
        entries = [x for x in entries if x["time_basis"] != "submission_time"]
    if len(entries) > 1500:  # keep every event tied to a finding, thin the rest evenly
        keep = [x for x in entries if x["finding_ids"]]
        rest = [x for x in entries if not x["finding_ids"]]
        step = max(1, len(rest) // max(1, 1500 - len(keep)))
        entries = sorted(keep + rest[::step], key=lambda x: x["at"])
    return {"entries": entries, "total_events": len(events), "omitted_submission_events": omitted, "layers": sorted({x["layer"] for x in entries}),
            "range": {"start": entries[0]["at"], "end": entries[-1]["at"]} if entries else None}


def forensics_analyst(db: Session, inv: str, emit) -> dict:
    stats = correlate(db, inv)
    emit("correlation", "forensics_analyst", f"Correlation: {stats['entities_total']} entities, {stats['cross_source_entities']} seen in multiple sources, {stats['chains']} cross-source chain(s)", **stats)
    findings = [f for f in db.scalars(select(Finding).where(Finding.investigation_id == inv)) if f.classification in ("suspicious", "confirmed_malicious")]
    ev_time = {e.id: _aw(e.timestamp) for e in db.scalars(select(SecurityEvent).where(SecurityEvent.investigation_id == inv)) if e.timestamp}
    steps = []
    for f in findings:
        phase = next((p for p, prefixes in PHASES if f.detector.startswith(prefixes)), None)
        times = [ev_time[e] for e in f.event_ids if e in ev_time]
        if phase and SEV_RANK[f.severity] >= 2:
            steps.append({"phase": phase, "at": min(times).isoformat() if times else None, "finding_id": f.id, "title": f.title, "evidence_ids": f.evidence_ids})
    steps.sort(key=lambda s: (s["at"] is None, s["at"] or ""))
    order = [p for p, _ in PHASES]
    seq = None
    if len({s["phase"] for s in steps}) >= 2:
        timed = [s for s in steps if s["at"]]
        monotonic = all(order.index(a["phase"]) <= order.index(b["phase"]) or a["phase"] == b["phase"] for a, b in zip(timed, timed[1:]))
        seq = {"label": "INFERRED attack sequence (hypothesis)", "basis": "Ordering of independently verified findings by their earliest evidence timestamp. Causality between steps is not observed.",
               "steps": steps[:25], "phases_in_expected_order": monotonic}
    # inconsistencies
    issues = []
    evidence = list(db.scalars(select(Evidence).where(Evidence.investigation_id == inv)))
    ranges = {}
    for e in evidence:
        ts = sorted(_aw(x.timestamp) for x in db.scalars(select(SecurityEvent).where(SecurityEvent.evidence_id == e.id))
                    if x.timestamp and x.action not in ("url_submitted", "file_submitted", "screenshot_submitted"))
        if ts:
            ranges[e.id] = (ts[0], ts[-1])
        m = e.meta or {}
        if e.kind in ("eml", "email_headers") and m.get("date") and ts and ts[0] > _aw(e.ingested_at) + timedelta(hours=1):
            issues.append({"evidence_id": e.id, "issue": f"Email Date header ({m['date']}) is later than the time the evidence was ingested; the header may be forged or the sender clock wrong."})
        if m.get("assumed_year"):
            issues.append({"evidence_id": e.id, "issue": f"Log timestamps have no year; {m['assumed_year']} was assumed. Ordering against other evidence is unreliable if the log is from another year."})
        if m.get("events_without_timestamp"):
            issues.append({"evidence_id": e.id, "issue": f"{m['events_without_timestamp']} event(s) have no parseable timestamp and are absent from the timeline."})
        if m.get("truncated"):
            issues.append({"evidence_id": e.id, "issue": "Evidence exceeded the processing limit and was truncated; later content was not analysed."})
    ids = sorted(ranges)
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            gap = max(ranges[a][0], ranges[b][0]) - min(ranges[a][1], ranges[b][1])
            if gap > timedelta(days=30):
                issues.append({"evidence_id": a, "issue": f"Evidence {a} and {b} are separated by {gap.days} days; they may not describe the same incident, so cross-source ordering between them is weak."})
    tl = build_timeline(db, inv)
    emit("correlation", "forensics_analyst", f"Timeline: {len(tl['entries'])} dated events across layers {', '.join(tl['layers']) or 'none'}; {len(issues)} inconsistency note(s)")
    return {"correlation": stats, "timeline_events": len(tl["entries"]), "timeline_range": tl["range"], "attack_sequence": seq, "inconsistencies": issues}
