"""Enrichment service: caching, rate-limit handling, source attribution, query timestamps."""
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..analysis.ioc import is_private_ip
from ..config import get_settings
from ..models import IntelCache, IntelRecord, utcnow
from .providers import Provider, RateLimited, active_providers


def enrich(db: Session, investigation_id: str, indicators: list[tuple[str, str]], providers: list[Provider] | None = None) -> dict:
    """Query every active provider for each (type, value). Returns counts; writes IntelRecord rows."""
    providers = providers if providers is not None else active_providers()
    ttl = timedelta(seconds=get_settings().intel_cache_ttl_seconds)
    limited: set[str] = set()
    stats = {"queried": 0, "cache_hits": 0, "records": 0, "errors": 0, "rate_limited": [], "skipped_private": 0, "providers": [p.name for p in providers]}
    already = {(r.indicator_type, r.indicator_value, r.source) for r in db.scalars(select(IntelRecord).where(IntelRecord.investigation_id == investigation_id))}
    for type_, value in indicators:
        if type_ == "ip" and is_private_ip(value):
            stats["skipped_private"] += 1
            continue
        for p in providers:
            if type_ not in p.types or p.name in limited or (type_, value, p.name) in already:
                continue
            cached = db.scalar(select(IntelCache).where(IntelCache.source == p.name, IntelCache.indicator_type == type_, IntelCache.indicator_value == value))
            now = utcnow()
            from_cache = False
            if cached and now - (cached.fetched_at if cached.fetched_at.tzinfo else cached.fetched_at.replace(tzinfo=now.tzinfo)) < ttl and p.name != "offline_bundle":
                result, from_cache, queried_at = cached.payload.get("result"), True, cached.fetched_at
                stats["cache_hits"] += 1
            else:
                queried_at = now
                try:
                    result = p.lookup(type_, value)
                    stats["queried"] += 1
                except RateLimited:
                    limited.add(p.name)
                    stats["rate_limited"].append(p.name)
                    db.add(IntelRecord(investigation_id=investigation_id, indicator_type=type_, indicator_value=value, source=p.name, source_reliability=p.reliability,
                                       verdict="rate_limited", summary="Provider rate limit reached; remaining lookups for this provider were skipped.", queried_at=now))
                    continue
                except Exception as e:  # network/provider failure: record it, never invent a result
                    stats["errors"] += 1
                    db.add(IntelRecord(investigation_id=investigation_id, indicator_type=type_, indicator_value=value, source=p.name, source_reliability=p.reliability,
                                       verdict="error", summary=f"Lookup failed: {type(e).__name__}", queried_at=now))
                    continue
                if p.name != "offline_bundle":
                    if cached:
                        cached.payload, cached.fetched_at = {"result": result}, now
                    else:
                        db.add(IntelCache(source=p.name, indicator_type=type_, indicator_value=value, payload={"result": result}, fetched_at=now))
            if result is None:
                continue  # source has no record: absence of intel is not recorded as "clean"
            db.add(IntelRecord(investigation_id=investigation_id, indicator_type=type_, indicator_value=value, source=p.name, source_reliability=p.reliability,
                               verdict=result["verdict"], summary=result["summary"][:500], reference=result.get("reference", "")[:500], raw=result.get("raw", {}),
                               queried_at=queried_at, from_cache=from_cache))
            stats["records"] += 1
    db.flush()
    return stats
