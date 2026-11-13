"""Investigation Verifier: independent re-inspection of every finding before it can influence the verdict.

It does not trust what detectors wrote. For each finding it re-reads the database and, where possible,
re-derives the claim from the preserved original evidence:
  1. cited evidence exists, belongs to the investigation and its stored bytes still hash to the recorded SHA-256
  2. cited events exist and belong to cited evidence
  3. every indicator named by the finding is actually present in the cited evidence
  4. countable / reproducible claims are recomputed (failure counts, URL scores, YARA matches)
  5. classification policy: 'confirmed_malicious' needs a malicious-class signature or two independent bases;
     ML, threat-intel and visual-similarity findings can never be confirmed on their own
  6. conflicts between sources are surfaced
It also verifies LLM narratives sentence by sentence and can request further analysis from the orchestrator.
"""
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..analysis.file import yara_scan
from ..analysis.ioc import extract_iocs
from ..analysis.url import analyse_url
from ..models import Evidence, Finding, Indicator, IntelRecord, SecurityEvent
from ..security.uploads import read_original

ENRICHABLE = {"ip", "domain", "url", "sha256"}


def verify_findings(db: Session, inv: str, looked_up: set | None = None) -> dict:
    evidence = {e.id: e for e in db.scalars(select(Evidence).where(Evidence.investigation_id == inv))}
    indicators = list(db.scalars(select(Indicator).where(Indicator.investigation_id == inv)))
    ind_by_ev: dict[str, set] = {}
    ind_type: dict[str, str] = {}
    for i in indicators:
        ind_by_ev.setdefault(i.evidence_id, set()).add(i.value)
        ind_type[i.value] = i.type
    intel = list(db.scalars(select(IntelRecord).where(IntelRecord.investigation_id == inv)))
    intel_by_val: dict[str, list] = {}
    for t in intel:
        intel_by_val.setdefault(t.indicator_value, []).append(t)

    integrity: dict[str, bool] = {}
    originals: dict[str, bytes] = {}
    for e in evidence.values():
        try:
            data = read_original(e.storage_path)
            integrity[e.id] = hashlib.sha256(data).hexdigest() == e.sha256
            originals[e.id] = data
        except Exception:
            integrity[e.id] = False

    findings = list(db.scalars(select(Finding).where(Finding.investigation_id == inv)))
    by_id = {f.id: f for f in findings}
    summary = {"checked": 0, "verified": 0, "rejected": 0, "downgraded": 0, "issues": [], "conflicts": [], "requests": []}

    for f in findings:
        summary["checked"] += 1
        notes, reject, downgrade_to = [], None, None
        # 1. evidence existence + integrity
        if not f.evidence_ids:
            reject = "finding cites no evidence"
        for eid in f.evidence_ids:
            if eid not in evidence:
                reject = f"cited evidence {eid} does not exist in this investigation"
            elif not integrity.get(eid):
                reject = f"stored bytes of evidence {eid} no longer match the SHA-256 recorded at ingestion"
        # 2. events
        events = []
        if not reject and f.event_ids:
            events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(f.event_ids))))
            if len(events) != len(set(f.event_ids)):
                reject = "one or more cited events do not exist"
            elif any(ev.evidence_id not in f.evidence_ids or ev.investigation_id != inv for ev in events):
                reject = "a cited event does not belong to the cited evidence"
        # 3. indicators present in cited evidence (or in the cited events' actor fields)
        if not reject:
            available = set().union(*(ind_by_ev.get(e, set()) for e in f.evidence_ids)) if f.evidence_ids else set()
            for ev in events:
                available |= {x for x in (ev.user, ev.host, ev.src_ip, ev.dst_ip, ev.domain, ev.url) if x}
            missing = [v for v in f.indicator_values if v and v not in available and str(v).lower() not in available]
            if missing:
                reject = f"indicator(s) not present in the cited evidence: {', '.join(str(m)[:60] for m in missing[:4])}"
        # 4. re-derivation
        if not reject:
            d = f.details or {}
            if f.detector in ("auth.brute_force", "auth.password_spraying"):
                n = sum(1 for ev in events if ev.category == "authentication" and ev.outcome == "failure" and ev.src_ip == d.get("source_ip"))
                claimed = min(d.get("failures", 0), 200)
                if n < claimed:
                    reject = f"recount found {n} failed-authentication events from {d.get('source_ip')} among cited events, finding claims {d.get('failures')}"
                else:
                    notes.append(f"recounted {n} cited failure events from {d.get('source_ip')}")
            elif f.detector == "auth.success_after_failures":
                if not any(ev.outcome == "success" and ev.user == d.get("account") and ev.src_ip == d.get("source_ip") for ev in events):
                    reject = "no cited event shows the claimed successful login"
                else:
                    notes.append("located the cited successful-login event")
            elif f.detector == "url.structure" and f.indicator_values:
                re_score = analyse_url(f.indicator_values[0]).get("score")
                if re_score != d.get("score"):
                    reject = f"re-analysis of the URL produced score {re_score}, finding recorded {d.get('score')}"
                else:
                    notes.append(f"URL re-analysed independently: score {re_score} reproduced")
            elif f.detector == "file.yara_match":
                again = {m["rule"] for eid in f.evidence_ids for m in yara_scan(originals.get(eid, b""))}
                if d.get("rule") not in again:
                    reject = f"re-scan of the preserved original did not reproduce YARA rule {d.get('rule')}"
                else:
                    notes.append(f"YARA rule {d.get('rule')} reproduced on the preserved original")
            elif f.detector == "process.suspicious_powershell":
                if not any(d.get("command_line", "")[:200] in str((ev.data or {}).get("command_line", "")) for ev in events):
                    reject = "the quoted command line is not present in the cited event"
                else:
                    notes.append("command line located in the cited event")
            elif f.detector.startswith("correlation.") and d.get("chain"):
                for hop in d["chain"]:
                    if not set(hop.get("evidence_ids", [])) <= set(f.evidence_ids):
                        reject = "a chain hop cites evidence that is not attached to the finding"
                if not reject:
                    notes.append(f"{len(d['chain'])} chain hop(s) each carry supporting evidence")
        # 5. classification policy
        if not reject and f.classification == "confirmed_malicious":
            d = f.details or {}
            ok = (f.basis == "signature" and d.get("rule_class") == "malicious") or \
                 (f.basis == "correlation" and d.get("behavioural_findings") and d.get("intel_sources") and not d.get("sample_intel_only")
                  and all(b in by_id for b in d["behavioural_findings"]))
            if not ok:
                downgrade_to = "unverified_intel" if f.basis == "threat_intel" else "suspicious"
                notes.append(f"'confirmed_malicious' is not permitted on basis '{f.basis}' without a malicious-class signature or two independent bases; downgraded to '{downgrade_to}'")
        # 6. conflicts
        if not reject and f.classification in ("suspicious", "confirmed_malicious"):
            for v in f.indicator_values:
                clean = [t for t in intel_by_val.get(v, []) if t.verdict == "clean"]
                if clean:
                    c = {"finding_id": f.id, "indicator": v, "conflict": f"finding is '{f.classification}' but {', '.join(sorted({t.source for t in clean}))} report(s) the indicator as clean"}
                    summary["conflicts"].append(c)
                    notes.append("CONFLICT: " + c["conflict"])
        if reject:
            f.verification_status, f.verification_notes = "rejected", reject
            summary["rejected"] += 1
            summary["issues"].append({"finding_id": f.id, "detector": f.detector, "issue": reject})
        elif downgrade_to:
            f.classification, f.verification_status, f.verification_notes = downgrade_to, "downgraded", "; ".join(notes)
            summary["downgraded"] += 1
        else:
            f.verification_status = "verified"
            f.verification_notes = "; ".join(notes) or "evidence, events and indicators cross-checked against the database"
            summary["verified"] += 1

    # same-URL disagreement between structural analysis and the ML model
    by_url: dict[str, dict] = {}
    for f in findings:
        if f.detector in ("url.structure", "ml.phishing_url") and f.indicator_values and f.verification_status != "rejected":
            by_url.setdefault(f.indicator_values[0], {})[f.detector] = f
    for url, pair in by_url.items():
        if "ml.phishing_url" in pair and pair.get("url.structure") is not None and pair["url.structure"].classification == "benign":
            summary["conflicts"].append({"finding_id": pair["ml.phishing_url"].id, "indicator": url,
                                         "conflict": "the ML classifier flags this URL while structural analysis found no indicators; treat the ML result as low-weight"})

    # requests for further analysis: suspicious indicators nobody has enriched yet
    enriched = set(intel_by_val) | {v for _, v in (looked_up or set())}  # looked up with no record is still 'done'
    want = []
    for f in findings:
        if f.verification_status in ("verified", "downgraded") and f.classification in ("suspicious", "confirmed_malicious"):
            for v in f.indicator_values:
                t = ind_type.get(v)
                if t in ENRICHABLE and v not in enriched and (t, v) not in want:
                    want.append((t, v))
    if want:
        summary["requests"].append({"agent": "threat_intel_analyst", "task": "enrich indicators referenced by suspicious findings that have no intelligence lookup yet", "indicators": [list(w) for w in want[:60]]})
    summary["evidence_integrity"] = integrity
    db.flush()
    return summary


def verify_narrative(db: Session, inv: str, sentences: list) -> dict:
    """Keep only sentences that cite existing, non-rejected findings and mention no indicator absent from the investigation."""
    valid_ids = {f.id for f in db.scalars(select(Finding).where(Finding.investigation_id == inv)) if f.verification_status in ("verified", "downgraded")}
    known = {i.value.lower() for i in db.scalars(select(Indicator).where(Indicator.investigation_id == inv))}
    kept, dropped = [], []
    for s in sentences if isinstance(sentences, list) else []:
        if not isinstance(s, dict) or not isinstance(s.get("text"), str):
            dropped.append({"text": str(s)[:200], "reason": "malformed sentence object"})
            continue
        ids = [i for i in (s.get("finding_ids") or []) if isinstance(i, str)]
        if not ids or not set(ids) <= valid_ids:
            dropped.append({"text": s["text"][:300], "reason": "cites no verified finding" if not ids else "cites unknown or rejected finding id(s)"})
            continue
        iocs = extract_iocs(s["text"])
        foreign = [v for k in ("ip", "domain", "url", "sha256", "email") for v in iocs[k] if v.lower() not in known and not any(v.lower() in kv for kv in known)]
        if foreign:
            dropped.append({"text": s["text"][:300], "reason": f"mentions indicator(s) not present in the evidence: {', '.join(foreign[:3])}"})
            continue
        kept.append({"text": s["text"][:600], "finding_ids": ids})
    return {"kept": kept, "dropped": dropped}
