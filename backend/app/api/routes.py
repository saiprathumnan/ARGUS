import json
from collections import Counter
from datetime import timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from ..agents import orchestrator
from ..agents.agents import build_timeline
from ..config import get_settings
from ..correlation.engine import SEV_RANK, build_graph
from ..db import get_db
from ..ingestion.base import PIPELINES
from ..ingestion import pipelines  # noqa: F401
from ..intel.providers import provider_status
from ..ml import anomaly as anomaly_ml
from ..ml import phishing as phishing_ml
from ..models import (AgentExecution, AuditLog, DetectionRule, Evidence, Finding, Indicator, IntelRecord, Investigation, MitreMapping, PipelineEvent,
                      Relationship, Report, SecurityEvent, new_id, utcnow)
from ..reports.export import to_html, to_markdown
from ..security.uploads import UploadRejected, sha256_bytes, store_original, validate_upload
from ..vision.similarity import load_references

router = APIRouter()


def iso(dt):
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def audit(db: Session, request: Request, action: str, target: str = "", **detail):
    db.add(AuditLog(actor="api-key" if get_settings().api_key else "local-analyst", action=action, target=target, detail=detail, remote_addr=request.client.host if request.client else ""))


def get_inv(db: Session, inv_id: str) -> Investigation:
    inv = db.get(Investigation, inv_id)
    if inv is None:
        raise HTTPException(404, "investigation not found")
    return inv


def inv_summary(db: Session, inv: Investigation) -> dict:
    counts = lambda model: db.scalar(select(func.count()).select_from(model).where(model.investigation_id == inv.id)) or 0
    return {"id": inv.id, "title": inv.title, "description": inv.description, "status": inv.status, "stage": inv.stage, "verdict": inv.verdict, "verdict_confidence": inv.verdict_confidence,
            "error": inv.error, "created_at": iso(inv.created_at), "started_at": iso(inv.started_at), "completed_at": iso(inv.completed_at),
            "counts": {"evidence": counts(Evidence), "indicators": db.scalar(select(func.count(func.distinct(Indicator.type + ":" + Indicator.value))).where(Indicator.investigation_id == inv.id)) or 0,
                       "events": counts(SecurityEvent), "findings": counts(Finding), "relationships": counts(Relationship), "rules": counts(DetectionRule)}}


def ev_dict(e: Evidence, full: bool = False) -> dict:
    d = {"id": e.id, "kind": e.kind, "name": e.original_name, "sha256": e.sha256, "size_bytes": e.size_bytes, "mime_type": e.mime_type, "source": e.source, "submitted_by": e.submitted_by,
         "ingested_at": iso(e.ingested_at), "status": e.status, "parse_error": e.parse_error}
    if full:
        d["meta"] = e.meta
    return d


def finding_dict(f: Finding) -> dict:
    return {"id": f.id, "detector": f.detector, "title": f.title, "description": f.description, "severity": f.severity, "classification": f.classification, "basis": f.basis,
            "confidence": f.confidence, "evidence_ids": f.evidence_ids, "event_ids": f.event_ids, "indicators": f.indicator_values, "details": f.details, "produced_by": f.produced_by,
            "verification_status": f.verification_status, "verification_notes": f.verification_notes, "created_at": iso(f.created_at)}


# ---------------------------------------------------------------- system
@router.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(select(1))
    return {"status": "ok", "service": "argus", "version": "1.0.0", "time": iso(utcnow())}


@router.get("/system")
def system(db: Session = Depends(get_db)):
    s = get_settings()
    pm, am = phishing_ml.model_metrics(), anomaly_ml.model_metrics()
    return {
        "version": "1.0.0", "environment": s.env, "auth_required": bool(s.api_key),
        "database": s.database_url.split(":")[0].split("+")[0],
        "limits": {"max_upload_bytes": s.max_upload_bytes, "max_evidence_per_investigation": s.max_evidence_per_investigation, "rate_limit_per_minute": s.rate_limit_per_minute},
        "evidence_kinds": sorted(PIPELINES),
        "network": {"live_url_fetch": s.allow_network_fetch},
        "threat_intel": {"offline_mode": s.intel_offline, "providers": provider_status()},
        "llm": {"provider": s.llm_provider, "model": s.llm_model if s.llm_provider != "none" else None, "role": "narrative phrasing only; never classification"},
        "models": {"phishing_url_classifier": {"installed": pm is not None, "metrics": pm}, "network_anomaly": {"installed": am is not None, "metrics": am}},
        "vision": {"reference_pages": [{"name": r["name"], "file": r["file"], "legitimate_domains": r.get("legitimate_domains", [])} for r in load_references()]},
        "totals": {"investigations": db.scalar(select(func.count()).select_from(Investigation)) or 0, "evidence": db.scalar(select(func.count()).select_from(Evidence)) or 0},
    }


@router.get("/audit")
def audit_log(limit: int = Query(100, le=500), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit))
    return [{"id": a.id, "at": iso(a.at), "actor": a.actor, "action": a.action, "target": a.target, "detail": a.detail, "remote_addr": a.remote_addr} for a in rows]


# ---------------------------------------------------------------- investigations
class InvestigationIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)


@router.post("/investigations", status_code=201)
def create_investigation(body: InvestigationIn, request: Request, db: Session = Depends(get_db)):
    inv = Investigation(title=body.title.strip(), description=body.description.strip())
    db.add(inv)
    db.flush()
    audit(db, request, "investigation.created", inv.id, title=inv.title)
    db.commit()
    return inv_summary(db, inv)


@router.get("/investigations")
def list_investigations(q: str = "", status: str = "", verdict: str = "", limit: int = Query(100, le=500), db: Session = Depends(get_db)):
    stmt = select(Investigation).order_by(Investigation.created_at.desc()).limit(limit)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(Investigation.title.ilike(like), Investigation.id.ilike(like), Investigation.description.ilike(like)))
    if status:
        stmt = stmt.where(Investigation.status == status)
    if verdict:
        stmt = stmt.where(Investigation.verdict == verdict)
    return [inv_summary(db, i) for i in db.scalars(stmt)]


@router.get("/investigations/{inv_id}")
def get_investigation(inv_id: str, db: Session = Depends(get_db)):
    inv = get_inv(db, inv_id)
    out = inv_summary(db, inv)
    out["evidence"] = [ev_dict(e) for e in db.scalars(select(Evidence).where(Evidence.investigation_id == inv_id).order_by(Evidence.ingested_at))]
    out["agents"] = [{"id": a.id, "agent": a.agent, "task": a.task, "status": a.status, "attempt": a.attempt, "error": (a.error or "").split("\n")[0] or None, "started_at": iso(a.started_at),
                      "finished_at": iso(a.finished_at)} for a in db.scalars(select(AgentExecution).where(AgentExecution.investigation_id == inv_id).order_by(AgentExecution.started_at, AgentExecution.id))]
    fs = list(db.scalars(select(Finding).where(Finding.investigation_id == inv_id)))
    out["finding_stats"] = {"by_severity": dict(Counter(f.severity for f in fs if f.verification_status != "rejected")), "by_classification": dict(Counter(f.classification for f in fs if f.verification_status != "rejected")),
                            "by_verification": dict(Counter(f.verification_status for f in fs))}
    return out


@router.delete("/investigations/{inv_id}", status_code=204)
def delete_investigation(inv_id: str, request: Request, db: Session = Depends(get_db)):
    inv = get_inv(db, inv_id)
    if inv.status == "running":
        raise HTTPException(409, "investigation is running")
    for model in (MitreMapping, DetectionRule, Report, PipelineEvent, AgentExecution, IntelRecord, Relationship, Finding, SecurityEvent, Indicator, Evidence):
        db.execute(delete(model).where(model.investigation_id == inv_id))
    db.delete(inv)
    audit(db, request, "investigation.deleted", inv_id)
    db.commit()


# ---------------------------------------------------------------- evidence
def _add_evidence(db: Session, request: Request, inv: Investigation, data: bytes, name: str, kind: str, mime: str, source: str, meta: dict | None = None) -> Evidence:
    s = get_settings()
    if inv.status == "running":
        raise HTTPException(409, "investigation is running; evidence cannot be added now")
    n = db.scalar(select(func.count()).select_from(Evidence).where(Evidence.investigation_id == inv.id)) or 0
    if n >= s.max_evidence_per_investigation:
        raise HTTPException(400, f"evidence limit ({s.max_evidence_per_investigation}) reached for this investigation")
    digest = sha256_bytes(data)
    if db.scalar(select(Evidence).where(Evidence.investigation_id == inv.id, Evidence.sha256 == digest, Evidence.kind == kind)):
        raise HTTPException(409, "identical evidence (same SHA-256) is already attached to this investigation")
    eid = new_id("EVD")
    path = store_original(inv.id, eid, data)
    ev = Evidence(id=eid, investigation_id=inv.id, kind=kind, original_name=name, sha256=digest, size_bytes=len(data), mime_type=mime, storage_path=str(path), source=source, meta=meta or {})
    db.add(ev)
    audit(db, request, "evidence.added", eid, investigation=inv.id, kind=kind, sha256=digest, size=len(data))
    db.commit()
    return ev


class UrlIn(BaseModel):
    url: str = Field(min_length=4, max_length=2048)


@router.post("/investigations/{inv_id}/evidence/url", status_code=201)
def add_url(inv_id: str, body: UrlIn, request: Request, db: Session = Depends(get_db)):
    inv = get_inv(db, inv_id)
    url = body.url.strip()
    if any(ord(c) < 32 for c in url) or " " in url:
        raise HTTPException(422, "URL contains whitespace or control characters")
    return ev_dict(_add_evidence(db, request, inv, url.encode(), url[:200], "url", "text/uri-list", "analyst_submission"))


class TextIn(BaseModel):
    kind: str = Field(pattern="^(email_headers|json_events|auth_log)$")
    content: str = Field(min_length=1)
    name: str = Field(default="pasted-text", max_length=200)


@router.post("/investigations/{inv_id}/evidence/text", status_code=201)
def add_text(inv_id: str, body: TextIn, request: Request, db: Session = Depends(get_db)):
    inv = get_inv(db, inv_id)
    try:
        kind, mime, name = validate_upload(body.content.encode(), body.name, body.kind)
    except UploadRejected as e:
        raise HTTPException(422, str(e))
    return ev_dict(_add_evidence(db, request, inv, body.content.encode(), name, kind, mime, "analyst_paste"))


@router.post("/investigations/{inv_id}/evidence/file", status_code=201)
async def add_file(inv_id: str, request: Request, file: UploadFile = File(...), kind: str = Form("auto"), source_url: str = Form(""), db: Session = Depends(get_db)):
    inv = get_inv(db, inv_id)
    limit = get_settings().max_upload_bytes
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"file exceeds the {limit} byte limit")
    try:
        k, mime, name = validate_upload(data, file.filename or "upload", kind)
    except UploadRejected as e:
        raise HTTPException(422, str(e))
    meta = {}
    if source_url.strip():
        if k != "screenshot":
            raise HTTPException(422, "source_url is only accepted for screenshots")
        if len(source_url) > 2048 or any(ord(c) < 33 for c in source_url.strip()):
            raise HTTPException(422, "invalid source_url")
        meta["source_url"] = source_url.strip()
    return ev_dict(_add_evidence(db, request, inv, data, name, k, mime, "analyst_upload", meta))


@router.get("/investigations/{inv_id}/evidence/{evidence_id}")
def evidence_detail(inv_id: str, evidence_id: str, db: Session = Depends(get_db)):
    get_inv(db, inv_id)
    e = db.get(Evidence, evidence_id)
    if e is None or e.investigation_id != inv_id:
        raise HTTPException(404, "evidence not found")
    out = ev_dict(e, full=True)
    out["indicators"] = [{"id": i.id, "type": i.type, "value": i.value, "context": i.context, "first_seen": iso(i.first_seen)} for i in db.scalars(select(Indicator).where(Indicator.evidence_id == evidence_id).limit(500))]
    evs = list(db.scalars(select(SecurityEvent).where(SecurityEvent.evidence_id == evidence_id).order_by(SecurityEvent.timestamp).limit(300)))
    out["events"] = [{"id": x.id, "at": iso(x.timestamp), "category": x.category, "action": x.action, "outcome": x.outcome, "summary": x.summary, "record_ref": x.record_ref, "duplicate_of": x.duplicate_of} for x in evs]
    out["event_total"] = db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.evidence_id == evidence_id)) or 0
    fs = [f for f in db.scalars(select(Finding).where(Finding.investigation_id == inv_id)) if evidence_id in f.evidence_ids]
    out["findings"] = [finding_dict(f) for f in sorted(fs, key=lambda f: -SEV_RANK[f.severity])]
    rels = [r for r in db.scalars(select(Relationship).where(Relationship.investigation_id == inv_id)) if evidence_id in r.evidence_ids and (r.source_type, r.source_value) != (r.target_type, r.target_value)]
    out["relationships"] = [{"id": r.id, "source": f"{r.source_type}:{r.source_value}", "target": f"{r.target_type}:{r.target_value}", "relation": r.relation, "basis": r.basis, "confidence": r.confidence,
                             "explanation": r.explanation, "count": r.count} for r in rels[:300]]
    return out


# ---------------------------------------------------------------- analysis
def _reset_derived(db: Session, inv_id: str):
    for model in (MitreMapping, Report, PipelineEvent, AgentExecution, IntelRecord, Relationship, Finding, SecurityEvent, Indicator):
        db.execute(delete(model).where(model.investigation_id == inv_id))
    for e in db.scalars(select(Evidence).where(Evidence.investigation_id == inv_id)):
        e.status, e.parse_error = "stored", None
        e.meta = {k: v for k, v in (e.meta or {}).items() if k == "source_url"}


@router.post("/investigations/{inv_id}/start", status_code=202)
def start_analysis(inv_id: str, request: Request, db: Session = Depends(get_db)):
    inv = get_inv(db, inv_id)
    if inv.status == "running":
        raise HTTPException(409, "analysis already running")
    if not db.scalar(select(func.count()).select_from(Evidence).where(Evidence.investigation_id == inv_id)):
        raise HTTPException(400, "add at least one evidence item before starting analysis")
    rerun = inv.status in ("completed", "failed")
    if rerun:
        _reset_derived(db, inv_id)  # originals are preserved; all derived data is rebuilt from them
    inv.status, inv.stage = "running", "evidence_collection"
    audit(db, request, "analysis.started", inv_id, rerun=rerun)
    db.commit()
    if not orchestrator.start(inv_id):
        raise HTTPException(409, "analysis already running")
    db.expire_all()
    return inv_summary(db, get_inv(db, inv_id))


@router.get("/investigations/{inv_id}/events")
def pipeline_events(inv_id: str, after: int = 0, db: Session = Depends(get_db)):
    inv = get_inv(db, inv_id)
    rows = db.scalars(select(PipelineEvent).where(PipelineEvent.investigation_id == inv_id, PipelineEvent.id > after).order_by(PipelineEvent.id).limit(500))
    return {"status": inv.status, "stage": inv.stage, "verdict": inv.verdict,
            "events": [{"id": p.id, "at": iso(p.at), "stage": p.stage, "actor": p.actor, "level": p.level, "message": p.message, "data": p.data} for p in rows]}


@router.get("/investigations/{inv_id}/agents/{execution_id}")
def agent_execution(inv_id: str, execution_id: str, db: Session = Depends(get_db)):
    a = db.get(AgentExecution, execution_id)
    if a is None or a.investigation_id != inv_id:
        raise HTTPException(404, "execution not found")
    return {"id": a.id, "agent": a.agent, "task": a.task, "status": a.status, "attempt": a.attempt, "output": a.output, "error": a.error, "started_at": iso(a.started_at), "finished_at": iso(a.finished_at)}


@router.get("/investigations/{inv_id}/findings")
def findings(inv_id: str, db: Session = Depends(get_db)):
    get_inv(db, inv_id)
    fs = sorted(db.scalars(select(Finding).where(Finding.investigation_id == inv_id)), key=lambda f: (f.verification_status == "rejected", -SEV_RANK[f.severity], -f.confidence))
    return [finding_dict(f) for f in fs]


@router.get("/investigations/{inv_id}/indicators")
def indicators(inv_id: str, type: str = "", q: str = "", db: Session = Depends(get_db)):
    get_inv(db, inv_id)
    stmt = select(Indicator).where(Indicator.investigation_id == inv_id)
    if type:
        stmt = stmt.where(Indicator.type == type)
    if q:
        stmt = stmt.where(Indicator.value.ilike(f"%{q}%"))
    merged: dict[tuple, dict] = {}
    for i in db.scalars(stmt):
        m = merged.setdefault((i.type, i.value), {"type": i.type, "value": i.value, "evidence_ids": [], "contexts": [], "first_seen": None})
        m["evidence_ids"].append(i.evidence_id)
        m["contexts"].append(i.context)
        if i.first_seen and (m["first_seen"] is None or iso(i.first_seen) < m["first_seen"]):
            m["first_seen"] = iso(i.first_seen)
    fs = [f for f in db.scalars(select(Finding).where(Finding.investigation_id == inv_id)) if f.verification_status != "rejected"]
    intel = list(db.scalars(select(IntelRecord).where(IntelRecord.investigation_id == inv_id)))
    for (t, v), m in merged.items():
        rel = [f for f in fs if v in f.indicator_values]
        m["finding_ids"] = [f.id for f in rel][:20]
        m["max_severity"] = max((f.severity for f in rel if f.classification in ("suspicious", "confirmed_malicious")), key=lambda s: SEV_RANK[s], default="info")
        m["intel"] = [{"source": x.source, "verdict": x.verdict, "reliability": x.source_reliability, "summary": x.summary, "reference": x.reference, "queried_at": iso(x.queried_at)} for x in intel if x.indicator_value == v]
    return sorted(merged.values(), key=lambda m: (-SEV_RANK[m["max_severity"]], m["type"], m["value"]))[:2000]


@router.get("/investigations/{inv_id}/graph")
def graph(inv_id: str, db: Session = Depends(get_db)):
    get_inv(db, inv_id)
    return build_graph(db, inv_id)


@router.get("/investigations/{inv_id}/timeline")
def timeline(inv_id: str, db: Session = Depends(get_db)):
    get_inv(db, inv_id)
    tl = build_timeline(db, inv_id)
    fx = db.scalar(select(AgentExecution).where(AgentExecution.investigation_id == inv_id, AgentExecution.agent == "forensics_analyst", AgentExecution.status == "completed").order_by(AgentExecution.started_at))
    tl["attack_sequence"] = (fx.output or {}).get("attack_sequence") if fx else None
    tl["inconsistencies"] = (fx.output or {}).get("inconsistencies", []) if fx else []
    return tl


@router.get("/investigations/{inv_id}/mitre")
def mitre(inv_id: str, db: Session = Depends(get_db)):
    get_inv(db, inv_id)
    return [{"id": m.id, "technique_id": m.technique_id, "technique_name": m.technique_name, "tactics": m.tactics, "rationale": m.rationale, "reference_url": m.reference_url, "confidence": m.confidence,
             "finding_id": m.finding_id} for m in db.scalars(select(MitreMapping).where(MitreMapping.investigation_id == inv_id).order_by(MitreMapping.technique_id))]


@router.get("/investigations/{inv_id}/rules")
def rules(inv_id: str, db: Session = Depends(get_db)):
    get_inv(db, inv_id)
    return [{"id": r.id, "rule_key": r.rule_key, "version": r.version, "format": r.format, "title": r.title, "content": r.content, "finding_ids": r.finding_ids, "evidence_ids": r.evidence_ids,
             "syntax_valid": r.syntax_valid, "validation": r.validation, "deployed": r.deployed, "created_at": iso(r.created_at)}
            for r in db.scalars(select(DetectionRule).where(DetectionRule.investigation_id == inv_id).order_by(DetectionRule.rule_key, DetectionRule.version.desc()))]


@router.get("/investigations/{inv_id}/intel")
def intel(inv_id: str, db: Session = Depends(get_db)):
    get_inv(db, inv_id)
    return [{"id": t.id, "indicator_type": t.indicator_type, "indicator": t.indicator_value, "source": t.source, "reliability": t.source_reliability, "verdict": t.verdict, "summary": t.summary,
             "reference": t.reference, "queried_at": iso(t.queried_at), "from_cache": t.from_cache} for t in db.scalars(select(IntelRecord).where(IntelRecord.investigation_id == inv_id))]


@router.get("/investigations/{inv_id}/report")
def report(inv_id: str, db: Session = Depends(get_db)):
    get_inv(db, inv_id)
    r = db.scalar(select(Report).where(Report.investigation_id == inv_id).order_by(Report.version.desc()))
    if r is None:
        raise HTTPException(404, "no report has been generated for this investigation yet")
    return {"id": r.id, "version": r.version, "created_at": iso(r.created_at), "narrative_source": r.narrative_source, "content": r.content}


@router.get("/investigations/{inv_id}/report/export")
def export_report(inv_id: str, request: Request, format: str = Query("html", pattern="^(html|md|json)$"), db: Session = Depends(get_db)):
    get_inv(db, inv_id)
    r = db.scalar(select(Report).where(Report.investigation_id == inv_id).order_by(Report.version.desc()))
    if r is None:
        raise HTTPException(404, "no report has been generated for this investigation yet")
    audit(db, request, "report.exported", r.id, format=format)
    db.commit()
    name = f"argus-{inv_id}-v{r.version}"
    if format == "html":
        return HTMLResponse(to_html(r.content), headers={"Content-Disposition": f'inline; filename="{name}.html"'})
    if format == "md":
        return PlainTextResponse(to_markdown(r.content), media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="{name}.md"'})
    return PlainTextResponse(json.dumps(r.content, indent=2, default=str), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{name}.json"'})


@router.get("/reports")
def all_reports(db: Session = Depends(get_db)):
    out = []
    for r in db.scalars(select(Report).order_by(Report.created_at.desc()).limit(200)):
        inv = db.get(Investigation, r.investigation_id)
        out.append({"id": r.id, "investigation_id": r.investigation_id, "title": inv.title if inv else "", "version": r.version, "created_at": iso(r.created_at), "verdict": r.content.get("verdict", {}).get("value"),
                    "confidence": r.content.get("verdict", {}).get("confidence"), "findings": len(r.content.get("findings", [])), "narrative_source": r.narrative_source})
    return out


# ---------------------------------------------------------------- search
@router.get("/search")
def search(q: str = Query(min_length=2, max_length=200), db: Session = Depends(get_db)):
    like = f"%{q.strip()}%"
    hits = []
    for i in db.scalars(select(Investigation).where(or_(Investigation.title.ilike(like), Investigation.id.ilike(like), Investigation.description.ilike(like))).limit(10)):
        hits.append({"type": "investigation", "investigation_id": i.id, "label": i.title, "sub": f"{i.id} · {i.status}"})
    for x in db.scalars(select(Indicator).where(Indicator.value.ilike(like)).limit(25)):
        hits.append({"type": "indicator", "investigation_id": x.investigation_id, "label": x.value, "sub": f"{x.type} · {x.evidence_id}", "ref": f"{x.type}:{x.value}"})
    for e in db.scalars(select(Evidence).where(or_(Evidence.original_name.ilike(like), Evidence.sha256.ilike(like), Evidence.id.ilike(like))).limit(10)):
        hits.append({"type": "evidence", "investigation_id": e.investigation_id, "label": e.original_name, "sub": f"{e.kind} · {e.id}", "ref": e.id})
    for f in db.scalars(select(Finding).where(or_(Finding.title.ilike(like), Finding.id.ilike(like))).limit(15)):
        hits.append({"type": "finding", "investigation_id": f.investigation_id, "label": f.title, "sub": f"{f.severity} · {f.id}", "ref": f.id})
    seen, uniq = set(), []
    for h in hits:
        k = (h["type"], h["investigation_id"], h["label"])
        if k not in seen:
            seen.add(k)
            uniq.append(h)
    return uniq[:50]


# ---------------------------------------------------------------- bundled sample scenarios
@router.get("/samples")
def list_samples():
    p = get_settings().data_dir / "samples" / "scenarios.json"
    return json.loads(p.read_text()) if p.exists() else []


@router.post("/samples/{scenario_id}", status_code=201)
def load_sample(scenario_id: str, request: Request, db: Session = Depends(get_db)):
    """Create an investigation pre-loaded with a bundled, clearly labelled SAMPLE dataset (synthetic evidence)."""
    base = get_settings().data_dir / "samples"
    scenarios = {s["id"]: s for s in list_samples()}
    sc = scenarios.get(scenario_id)
    if sc is None:
        raise HTTPException(404, "unknown sample scenario")
    inv = Investigation(title=f"[SAMPLE] {sc['title']}", description=f"Bundled synthetic sample dataset. {sc['description']} Expected outcome: {sc['expected_verdict']}.")
    db.add(inv)
    db.flush()
    audit(db, request, "investigation.created", inv.id, sample=scenario_id)
    db.commit()
    for item in sc["evidence"]:
        if item["kind"] == "url":
            _add_evidence(db, request, inv, item["url"].encode(), item["url"][:200], "url", "text/uri-list", "bundled_sample_dataset")
        else:
            path = (base / item["file"]).resolve()
            if base.resolve() not in path.parents:
                raise HTTPException(500, "invalid sample path")
            data = path.read_bytes()
            k, mime, name = validate_upload(data, path.name, item["kind"])
            _add_evidence(db, request, inv, data, name, k, mime, "bundled_sample_dataset", {"source_url": item["source_url"]} if item.get("source_url") else {})
    return inv_summary(db, inv)
