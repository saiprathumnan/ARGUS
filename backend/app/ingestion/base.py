"""Common normalised schema produced by every ingestion pipeline, and the pipeline registry."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable


@dataclass
class IndicatorDraft:
    type: str
    value: str
    context: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass
class EventDraft:
    category: str
    action: str
    timestamp: datetime | None = None
    outcome: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    domain: str | None = None
    url: str | None = None
    user: str | None = None
    host: str | None = None
    summary: str = ""
    data: dict = field(default_factory=dict)
    record_ref: str = ""
    key: str = ""  # local key so findings/relations can reference events before they have DB ids


@dataclass
class FindingDraft:
    detector: str
    title: str
    severity: str
    classification: str
    basis: str
    confidence: float
    description: str = ""
    indicator_values: list = field(default_factory=list)
    event_keys: list = field(default_factory=list)
    details: dict = field(default_factory=dict)


@dataclass
class RelationDraft:
    source: tuple  # (type, value)
    target: tuple
    relation: str
    basis: str  # observed | derived | inferred
    confidence: float
    explanation: str = ""
    event_keys: list = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    count: int = 1


@dataclass
class ParsedEvidence:
    meta: dict = field(default_factory=dict)
    indicators: list[IndicatorDraft] = field(default_factory=list)
    events: list[EventDraft] = field(default_factory=list)
    findings: list[FindingDraft] = field(default_factory=list)
    relations: list[RelationDraft] = field(default_factory=list)

    def add_ioc(self, type_: str, value: str, context: str = "", ts: datetime | None = None):
        if value:
            self.indicators.append(IndicatorDraft(type_, value[:2000], context, ts, ts))


@dataclass
class IngestContext:
    evidence_id: str
    investigation_id: str
    filename: str
    ingested_at: datetime
    meta: dict  # analyst-supplied provenance (e.g. source_url for a screenshot)


PIPELINES: dict[str, Callable[[bytes, IngestContext], ParsedEvidence]] = {}


def pipeline(kind: str):
    """Register an ingestion pipeline. New evidence formats are added by decorating one function."""
    def deco(fn):
        PIPELINES[kind] = fn
        return fn
    return deco


def to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def parse_ts(value) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    s = str(value).strip()
    try:
        return to_utc(datetime.fromisoformat(s.replace("Z", "+00:00")))
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return to_utc(datetime.strptime(s, fmt))
        except ValueError:
            continue
    return None
