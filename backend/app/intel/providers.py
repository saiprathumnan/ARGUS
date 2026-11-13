"""Threat-intelligence providers. Each returns reputation data with source attribution; reputation is never
treated as verified evidence. Providers without an API key are skipped, not faked."""
import base64
import json
from functools import lru_cache

import httpx

from ..config import get_settings


class RateLimited(Exception):
    pass


class Provider:
    name = "base"
    reliability = "unrated"
    types: set[str] = set()

    def available(self) -> bool:
        return True

    def lookup(self, type_: str, value: str) -> dict | None:
        """Return {'verdict','summary','reference','raw'} or None when the source has no record."""
        raise NotImplementedError


class OfflineBundle(Provider):
    name = "offline_bundle"
    reliability = "sample"
    types = {"ip", "domain", "url", "sha256"}

    @staticmethod
    @lru_cache
    def _index() -> dict:
        p = get_settings().data_dir / "intel" / "offline_intel.json"
        if not p.exists():
            return {}
        return {(r["type"], r["value"].lower()): r for r in json.loads(p.read_text())["records"]}

    def lookup(self, type_, value):
        r = self._index().get((type_, value.lower()))
        if not r:
            return None
        return {"verdict": r["verdict"], "summary": r["summary"], "reference": r["reference"], "raw": {"sample": True}}


class _Http(Provider):
    timeout = 10.0
    transport: httpx.BaseTransport | None = None  # injectable for tests

    def _get(self, url: str, headers: dict, params: dict | None = None) -> dict | None:
        with httpx.Client(timeout=self.timeout, transport=self.transport) as c:
            r = c.get(url, headers=headers, params=params)
        if r.status_code == 429:
            raise RateLimited(self.name)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()


class VirusTotal(_Http):
    name = "virustotal"
    reliability = "community-aggregated"
    types = {"ip", "domain", "url", "sha256"}

    def available(self):
        return bool(get_settings().virustotal_api_key)

    def lookup(self, type_, value):
        path = {"ip": f"ip_addresses/{value}", "domain": f"domains/{value}", "sha256": f"files/{value}",
                "url": "urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")}[type_]
        doc = self._get(f"https://www.virustotal.com/api/v3/{path}", {"x-apikey": get_settings().virustotal_api_key})
        if not doc:
            return None
        stats = (doc.get("data", {}).get("attributes", {}) or {}).get("last_analysis_stats", {}) or {}
        mal, sus, total = stats.get("malicious", 0), stats.get("suspicious", 0), sum(stats.values()) or 0
        verdict = "malicious" if mal >= 3 else "suspicious" if (mal or sus) else "clean" if total else "unknown"
        gui = {"ip": "ip-address", "domain": "domain", "sha256": "file", "url": "url"}[type_]
        return {"verdict": verdict, "summary": f"{mal} malicious / {sus} suspicious of {total} engines", "reference": f"https://www.virustotal.com/gui/{gui}/{value if type_ != 'url' else ''}", "raw": {"last_analysis_stats": stats}}


class AbuseIPDB(_Http):
    name = "abuseipdb"
    reliability = "community-reported"
    types = {"ip"}

    def available(self):
        return bool(get_settings().abuseipdb_api_key)

    def lookup(self, type_, value):
        doc = self._get("https://api.abuseipdb.com/api/v2/check", {"Key": get_settings().abuseipdb_api_key, "Accept": "application/json"}, {"ipAddress": value, "maxAgeInDays": "90"})
        d = (doc or {}).get("data")
        if not d:
            return None
        score = d.get("abuseConfidenceScore", 0)
        verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean" if d.get("totalReports", 0) == 0 else "unknown"
        return {"verdict": verdict, "summary": f"abuse confidence {score}%, {d.get('totalReports', 0)} reports, ISP {d.get('isp', '?')}", "reference": f"https://www.abuseipdb.com/check/{value}",
                "raw": {k: d.get(k) for k in ("abuseConfidenceScore", "totalReports", "countryCode", "usageType", "isp", "lastReportedAt")}}


class OTX(_Http):
    name = "otx"
    reliability = "community-pulses"
    types = {"ip", "domain", "sha256"}

    def available(self):
        return bool(get_settings().otx_api_key)

    def lookup(self, type_, value):
        section = {"ip": "IPv4", "domain": "domain", "sha256": "file"}[type_]
        doc = self._get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general", {"X-OTX-API-KEY": get_settings().otx_api_key})
        if not doc:
            return None
        n = (doc.get("pulse_info") or {}).get("count", 0)
        names = [p.get("name", "")[:80] for p in (doc.get("pulse_info") or {}).get("pulses", [])[:5]]
        return {"verdict": "suspicious" if n else "unknown", "summary": f"referenced in {n} OTX pulse(s)" + (": " + "; ".join(names) if names else ""),
                "reference": f"https://otx.alienvault.com/indicator/{section.lower()}/{value}", "raw": {"pulse_count": n, "pulses": names}}


def active_providers() -> list[Provider]:
    s = get_settings()
    providers: list[Provider] = [OfflineBundle()]
    if not s.intel_offline:
        providers += [p for p in (VirusTotal(), AbuseIPDB(), OTX()) if p.available()]
    return providers


def provider_status() -> list[dict]:
    s = get_settings()
    rows = [{"name": "offline_bundle", "enabled": True, "reason": "bundled sample intelligence (fictional indicators)"}]
    for p, key in ((VirusTotal(), s.virustotal_api_key), (AbuseIPDB(), s.abuseipdb_api_key), (OTX(), s.otx_api_key)):
        rows.append({"name": p.name, "enabled": bool(key) and not s.intel_offline,
                     "reason": "offline mode (ARGUS_INTEL_OFFLINE=true)" if s.intel_offline else ("API key configured" if key else "no API key configured")})
    return rows
