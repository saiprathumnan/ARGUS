"""ORCHESTRATOR: plans the investigation, dispatches agents, tracks execution, handles failures and
verifier requests, and derives the verdict. Lightweight custom orchestration (no agent framework):
the pipeline is a fixed, auditable sequence, which is what a forensic process needs (ADR-003)."""
import threading
import traceback

from sqlalchemy import select

from ..config import get_settings
from ..correlation.engine import SEV_RANK
from ..db import session_scope
from ..mitre.mapping import map_findings
from ..models import AgentExecution, AuditLog, Finding, Investigation, PipelineEvent, utcnow
from ..reports.generator import generate_report
from ..rules.generator import generate_rules
from . import agents as A
from .verifier import verify_findings

_running: set[str] = set()
_lock = threading.Lock()


def emit(inv: str, stage: str, actor: str, message: str, level: str = "info", **data):
    with session_scope() as db:
        db.add(PipelineEvent(investigation_id=inv, stage=stage, actor=actor, level=level, message=message[:600], data=data))


def _set(inv: str, **fields):
    with session_scope() as db:
        row = db.get(Investigation, inv)
        for k, v in fields.items():
            setattr(row, k, v)


def _run_agent(inv: str, stage: str, agent: str, task: str, fn, required: bool, attempt: int = 1):
    """Run one agent task in its own transaction. Returns (ok, output)."""
    with session_scope() as db:
        ex = AgentExecution(investigation_id=inv, agent=agent, task=task, status="running", attempt=attempt, started_at=utcnow())
        db.add(ex)
        db.flush()
        ex_id = ex.id
    emit(inv, stage, agent, f"Started: {task}", execution_id=ex_id)
    try:
        with session_scope() as db:
            output = fn(db)
        with session_scope() as db:
            ex = db.get(AgentExecution, ex_id)
            skipped = isinstance(output, dict) and output.get("skipped")
            ex.status, ex.output, ex.finished_at = ("skipped" if skipped else "completed"), output, utcnow()
        emit(inv, stage, agent, ("Skipped: " + output.get("reason", "")) if skipped else f"Completed: {task}", execution_id=ex_id)
        return True, output
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        with session_scope() as db:
            ex = db.get(AgentExecution, ex_id)
            ex.status, ex.error, ex.finished_at = "failed", (err + "\n" + traceback.format_exc()[-1500:])[:4000], utcnow()
        emit(inv, stage, agent, f"Failed: {task} - {err[:200]}", level="error", execution_id=ex_id)
        if required:
            raise
        return False, {"error": err}


def compute_verdict(db, inv: str) -> tuple[str, float]:
    """Deterministic verdict from verified findings. An LLM never participates."""
    fs = [f for f in db.scalars(select(Finding).where(Finding.investigation_id == inv)) if f.verification_status in ("verified", "downgraded")]
    if not fs:
        return "insufficient_evidence", 0.9
    confirmed = [f for f in fs if f.classification == "confirmed_malicious"]
    if confirmed:
        return "malicious", round(max(f.confidence for f in confirmed), 3)
    # suspicious findings that rest on evidence (not on a model or on reputation alone) and are at least medium severity
    strong = [f for f in fs if f.classification == "suspicious" and SEV_RANK[f.severity] >= 2 and f.basis in ("deterministic", "signature", "correlation")]
    if strong:
        miss = 1.0
        for f in sorted(strong, key=lambda f: -f.confidence)[:6]:
            miss *= 1 - 0.6 * f.confidence
        return "suspicious", round(min(0.95, 1 - miss), 3)
    weak = [f for f in fs if f.classification in ("suspicious", "unverified_intel", "insufficient_evidence") and f.severity != "info"]
    if weak:
        return "insufficient_evidence", round(min(0.8, 0.4 + 0.05 * len(weak)), 3)
    if any(f.classification == "benign" for f in fs):
        return "benign", 0.5 if len(fs) < 3 else 0.6
    return "insufficient_evidence", 0.6


def run_investigation(inv: str):
    try:
        _set(inv, status="running", stage="evidence_collection", started_at=utcnow(), error=None, verdict=None, verdict_confidence=None)
        with session_scope() as db:
            plan = A.plan(db, inv)
            db.add(AgentExecution(investigation_id=inv, agent="orchestrator", task="create investigation plan", status="completed", output=plan, started_at=utcnow(), finished_at=utcnow()))
        emit(inv, "evidence_collection", "orchestrator", f"Plan created: {len(plan['tasks'])} tasks for " + ", ".join(f"{n} {k}" for k, n in plan["evidence_kinds"].items()), plan=plan["tasks"])

        def E(db):
            """Activity emitter bound to the agent's own session: commits the agent's progress so far, then the event.
            (A second connection would dead-lock against the agent's open write transaction on SQLite.)"""
            def _emit(stage, actor, msg, level="info", **d):
                db.add(PipelineEvent(investigation_id=inv, stage=stage, actor=actor, level=level, message=msg[:600], data=d))
                db.commit()
            return _emit

        _, ev_out = _run_agent(inv, "evidence_collection", "evidence_analyst", plan["tasks"][0]["task"], lambda db: A.evidence_analyst(db, inv, E(db)), required=True)
        if ev_out["evidence"] and ev_out["failed"] == len(ev_out["evidence"]):
            raise RuntimeError("no evidence item could be parsed")

        _set(inv, stage="processing")
        _run_agent(inv, "processing", "network_analyst", plan["tasks"][1]["task"], lambda db: A.network_analyst(db, inv, E(db)), required=False)
        _, ti_out = _run_agent(inv, "processing", "threat_intel_analyst", plan["tasks"][2]["task"], lambda db: A.threat_intel_analyst(db, inv, E(db)), required=False)
        looked_up = {tuple(x) for x in (ti_out or {}).get("looked_up", [])}

        _set(inv, stage="correlation")
        _run_agent(inv, "correlation", "forensics_analyst", plan["tasks"][3]["task"], lambda db: A.forensics_analyst(db, inv, E(db)), required=True)

        _set(inv, stage="verification")
        _, v = _run_agent(inv, "verification", "investigation_verifier", plan["tasks"][4]["task"], lambda db: verify_findings(db, inv, looked_up), required=True)
        emit(inv, "verification", "investigation_verifier", f"{v['verified']} finding(s) verified, {v['rejected']} rejected, {v['downgraded']} downgraded, {len(v['conflicts'])} conflict(s)",
             level="warn" if v["rejected"] or v["conflicts"] else "info")
        for req in v.get("requests", []):  # the verifier may ask for more analysis: honour it once, then verify again
            if req["agent"] == "threat_intel_analyst":
                emit(inv, "verification", "orchestrator", f"Verifier requested further analysis: {req['task']} ({len(req['indicators'])} indicator(s))")
                only = [tuple(x) for x in req["indicators"]]
                _run_agent(inv, "verification", "threat_intel_analyst", "follow-up enrichment requested by the verifier", lambda db: A.threat_intel_analyst(db, inv, E(db), only=only, stage="verification"), required=False, attempt=2)
                looked_up |= set(only)
                _run_agent(inv, "verification", "forensics_analyst", "re-run corroboration after follow-up enrichment", lambda db: _recorroborate(db, inv), required=False, attempt=2)
                _, v = _run_agent(inv, "verification", "investigation_verifier", "re-verify after follow-up analysis", lambda db: verify_findings(db, inv, looked_up), required=True, attempt=2)

        with session_scope() as db:
            verdict, conf = compute_verdict(db, inv)
            if v.get("conflicts"):
                conf = round(conf * 0.85, 3)
            row = db.get(Investigation, inv)
            row.verdict, row.verdict_confidence = verdict, conf
        emit(inv, "verification", "orchestrator", f"Verdict derived from verified findings: {verdict} (confidence {conf:.0%})", verdict=verdict)

        _run_agent(inv, "verification", "forensics_analyst", plan["tasks"][5]["task"], lambda db: {"mappings_created": map_findings(db, inv)}, required=False)
        _run_agent(inv, "verification", "orchestrator", plan["tasks"][6]["task"],
                   lambda db: {"rules": [{"id": r.id, "format": r.format, "title": r.title, "syntax_valid": r.syntax_valid} for r in generate_rules(db, inv)],
                               "note": "Rules are stored for review only. ARGUS never deploys rules."}, required=False)
        _run_agent(inv, "verification", "report_generator", plan["tasks"][7]["task"], lambda db: (lambda r: {"report_id": r.id, "version": r.version, "narrative_source": r.narrative_source})(generate_report(db, inv)), required=True)

        _set(inv, status="completed", stage="completed", completed_at=utcnow())
        emit(inv, "completed", "orchestrator", "Investigation completed")
        with session_scope() as db:
            db.add(AuditLog(actor="system", action="investigation.completed", target=inv, detail={"verdict": verdict}))
    except Exception as e:
        _set(inv, status="failed", stage="failed", error=f"{type(e).__name__}: {e}"[:1000], completed_at=utcnow())
        emit(inv, "failed", "orchestrator", f"Investigation failed: {type(e).__name__}: {e}"[:500], level="error")
    finally:
        with _lock:
            _running.discard(inv)


def _recorroborate(db, inv: str) -> dict:
    """After follow-up enrichment only the intel-corroboration step needs to run again."""
    from ..correlation.engine import correlate
    before = {f.id for f in db.scalars(select(Finding).where(Finding.investigation_id == inv))}
    existing = {(f.detector, tuple(f.indicator_values)) for f in db.scalars(select(Finding).where(Finding.investigation_id == inv)) if f.produced_by == "correlation_engine"}
    correlate(db, inv)
    removed = 0
    for f in list(db.scalars(select(Finding).where(Finding.investigation_id == inv))):
        if f.id not in before and (f.detector, tuple(f.indicator_values)) in existing:
            db.delete(f)  # drop exact repeats of findings the first correlation pass already produced
            removed += 1
    db.flush()
    return {"new_findings": len({f.id for f in db.scalars(select(Finding).where(Finding.investigation_id == inv))} - before), "repeats_discarded": removed}


def start(inv: str) -> bool:
    with _lock:
        if inv in _running:
            return False
        _running.add(inv)
    if get_settings().run_inline:
        run_investigation(inv)
    else:
        _pool().submit(run_investigation, inv)
    return True


_executor = None


def _pool():
    """Bounded worker pool: at most `ARGUS_WORKERS` investigations analyse at once, the rest queue."""
    global _executor
    if _executor is None:
        from concurrent.futures import ThreadPoolExecutor
        _executor = ThreadPoolExecutor(max_workers=max(1, get_settings().workers), thread_name_prefix="argus-worker")
    return _executor


def warm_up():
    """Import heavy libraries and load models once, on the main thread, before any worker needs them.
    (Lazy imports from several worker threads at once can dead-lock Python's import system.)"""
    from ..analysis.file import _yara_rules
    from ..ml import anomaly, phishing
    from ..vision.similarity import load_references
    import scapy.all  # noqa: F401
    import sigma.rule  # noqa: F401
    phishing._load(); anomaly._load(); _yara_rules(); load_references()
    from ..rules.generator import labelled_corpus
    labelled_corpus()
