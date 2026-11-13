"""Relational schema. All timestamps are stored in UTC. Provenance chain:
Evidence -> (Indicator | SecurityEvent) -> Finding -> (MitreMapping | DetectionRule | Report)."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import event
from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(dt: datetime | None) -> str | None:
    """ISO-8601 with an explicit UTC offset. SQLite returns naive datetimes; they are UTC by construction."""
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("INV"))
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    # created | running | completed | failed
    status: Mapped[str] = mapped_column(String(20), default="created", index=True)
    # idle | evidence_collection | processing | correlation | verification | completed | failed
    stage: Mapped[str] = mapped_column(String(30), default="idle")
    # malicious | suspicious | benign | insufficient_evidence | None (not analysed)
    verdict: Mapped[str | None] = mapped_column(String(30), nullable=True)
    verdict_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    evidence = relationship("Evidence", back_populates="investigation", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("EVD"))
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(30))  # url | eml | email_headers | json_events | auth_log | pcap | file | pdf | screenshot
    original_name: Mapped[str] = mapped_column(String(300))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    mime_type: Mapped[str] = mapped_column(String(120), default="application/octet-stream")
    storage_path: Mapped[str] = mapped_column(String(500))  # original bytes, preserved read-only
    source: Mapped[str] = mapped_column(String(60), default="analyst_upload")  # provenance: how it entered ARGUS
    submitted_by: Mapped[str] = mapped_column(String(120), default="local-analyst")
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(20), default="stored")  # stored | parsed | failed
    parse_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)  # extracted metadata (headers, counts, dimensions...)

    investigation = relationship("Investigation", back_populates="evidence")


class Indicator(Base):
    __tablename__ = "indicators"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("IOC"))
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(20))  # ip | domain | url | email | sha256 | user | host | filename
    value: Mapped[str] = mapped_column(String(2100))
    context: Mapped[str] = mapped_column(String(300), default="")  # where in the evidence it was found
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (Index("ix_indicator_lookup", "investigation_id", "type", "value"),)


class SecurityEvent(Base):
    """Common normalised event schema shared by every ingestion pipeline."""
    __tablename__ = "security_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("EVT"))
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    category: Mapped[str] = mapped_column(String(30))  # authentication | process | network | dns | email | web | file
    action: Mapped[str] = mapped_column(String(60))
    outcome: Mapped[str | None] = mapped_column(String(20), nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(300), nullable=True)
    url: Mapped[str | None] = mapped_column(String(2100), nullable=True)
    user: Mapped[str | None] = mapped_column(String(200), nullable=True)
    host: Mapped[str | None] = mapped_column(String(200), nullable=True)
    summary: Mapped[str] = mapped_column(String(500), default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)  # normalised extra fields
    record_ref: Mapped[str] = mapped_column(String(80), default="")  # pointer into the original evidence (line/packet/record no.)
    fingerprint: Mapped[str] = mapped_column(String(64), default="", index=True)  # duplicate detection
    duplicate_of: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("FND"))
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    detector: Mapped[str] = mapped_column(String(80))  # e.g. url.typosquat, auth.brute_force
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10))  # info | low | medium | high | critical
    # confirmed_malicious | suspicious | benign | insufficient_evidence | unverified_intel
    classification: Mapped[str] = mapped_column(String(30))
    # deterministic | signature | ml_model | threat_intel | visual_similarity | correlation
    basis: Mapped[str] = mapped_column(String(30))
    confidence: Mapped[float] = mapped_column(Float)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    indicator_values: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    produced_by: Mapped[str] = mapped_column(String(60), default="detection_engine")
    # unverified | verified | rejected | downgraded
    verification_status: Mapped[str] = mapped_column(String(20), default="unverified")
    verification_notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Relationship(Base):
    """Edge of the evidence graph. Every edge carries the evidence that supports it."""
    __tablename__ = "relationships"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("REL"))
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    source_type: Mapped[str] = mapped_column(String(20))
    source_value: Mapped[str] = mapped_column(String(2100))
    target_type: Mapped[str] = mapped_column(String(20))
    target_value: Mapped[str] = mapped_column(String(2100))
    relation: Mapped[str] = mapped_column(String(40))  # contains | hosted_on | resolves_to | connects_to | queried | sent_from | authenticated_from | same_entity_across_sources | precedes
    # observed (seen directly in evidence) | derived (structural, e.g. URL -> its hostname) | inferred (temporal / heuristic)
    basis: Mapped[str] = mapped_column(String(12))
    confidence: Mapped[float] = mapped_column(Float)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    explanation: Mapped[str] = mapped_column(String(500), default="")


class IntelRecord(Base):
    __tablename__ = "intel_records"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("TI"))
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True, index=True)
    indicator_type: Mapped[str] = mapped_column(String(20))
    indicator_value: Mapped[str] = mapped_column(String(2100))
    source: Mapped[str] = mapped_column(String(60))  # offline_bundle | virustotal | abuseipdb | otx
    source_reliability: Mapped[str] = mapped_column(String(20), default="unrated")
    verdict: Mapped[str] = mapped_column(String(20))  # malicious | suspicious | clean | unknown | error | rate_limited
    summary: Mapped[str] = mapped_column(String(500), default="")
    reference: Mapped[str] = mapped_column(String(500), default="")
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    queried_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    from_cache: Mapped[bool] = mapped_column(Boolean, default=False)


class IntelCache(Base):
    __tablename__ = "intel_cache"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(60))
    indicator_type: Mapped[str] = mapped_column(String(20))
    indicator_value: Mapped[str] = mapped_column(String(2100))
    payload: Mapped[dict] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("source", "indicator_type", "indicator_value"),)


class AgentExecution(Base):
    __tablename__ = "agent_executions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("AGX"))
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    agent: Mapped[str] = mapped_column(String(40))
    task: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending | running | completed | failed | skipped
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    input_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PipelineEvent(Base):
    """Append-only activity stream consumed by the frontend. Only real execution steps are written here."""
    __tablename__ = "pipeline_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    stage: Mapped[str] = mapped_column(String(30))
    actor: Mapped[str] = mapped_column(String(40))
    level: Mapped[str] = mapped_column(String(10), default="info")  # info | warn | error
    message: Mapped[str] = mapped_column(String(600))
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("MTR"))
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    technique_id: Mapped[str] = mapped_column(String(20))
    technique_name: Mapped[str] = mapped_column(String(200))
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    rationale: Mapped[str] = mapped_column(Text)
    reference_url: Mapped[str] = mapped_column(String(300))
    confidence: Mapped[float] = mapped_column(Float)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("RUL"))
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    rule_key: Mapped[str] = mapped_column(String(120))  # stable identity across versions
    version: Mapped[int] = mapped_column(Integer, default=1)
    format: Mapped[str] = mapped_column(String(10))  # sigma | yara
    title: Mapped[str] = mapped_column(String(300))
    content: Mapped[str] = mapped_column(Text)
    finding_ids: Mapped[list] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    syntax_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    validation: Mapped[dict] = mapped_column(JSON, default=dict)  # issues, unsupported fields, TP/FP results
    deployed: Mapped[bool] = mapped_column(Boolean, default=False)  # ARGUS never sets this itself
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("RPT"))
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    content: Mapped[dict] = mapped_column(JSON)
    narrative_source: Mapped[str] = mapped_column(String(200), default="deterministic_template")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(200), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    remote_addr: Mapped[str] = mapped_column(String(64), default="")


def _clip(mapper, connection, target):
    """Clip strings to their column length. SQLite ignores VARCHAR limits, PostgreSQL enforces them;
    evidence-derived text (titles, summaries) must never be able to abort an insert."""
    for col in mapper.columns:
        length = getattr(col.type, "length", None)
        if length:
            v = getattr(target, col.key, None)
            if isinstance(v, str) and len(v) > length:
                setattr(target, col.key, v[:length])


event.listen(Base, "before_insert", _clip, propagate=True)
event.listen(Base, "before_update", _clip, propagate=True)
