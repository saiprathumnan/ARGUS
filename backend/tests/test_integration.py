"""Integration + end-to-end tests: API, persistence, orchestration, intel adapters, correlation, verification, reports."""
import json

import httpx
import pytest
from sqlalchemy import select

from app.agents import llm as llm_mod
from app.agents.verifier import verify_findings, verify_narrative
from app.db import session_scope
from app.intel import providers as prov
from app.intel.service import enrich
from app.models import AuditLog, Evidence, Finding, IntelCache, IntelRecord, Investigation, Relationship
from conftest import SAMPLES

SCENARIOS = json.loads((SAMPLES / "scenarios.json").read_text())


# ---------------- end-to-end: every required scenario against ground truth ----------------
@pytest.mark.parametrize("sc", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_scenario_end_to_end(client, scenario_runs, sc):
    d = scenario_runs(sc["id"])
    assert d["status"] == "completed", d["error"]
    assert d["verdict"] == sc["expected_verdict"]
    fs = client.get(f"/api/investigations/{d['id']}/findings").json()
    detectors = {f["detector"] for f in fs if f["verification_status"] != "rejected"}
    assert set(sc["expected_detectors"]) <= detectors, set(sc["expected_detectors"]) - detectors
    assert all(f["verification_status"] in ("verified", "downgraded") for f in fs), [f for f in fs if f["verification_status"] == "rejected"]
    assert all(f["evidence_ids"] for f in fs)                                    # no finding without evidence
    assert not any(f["classification"] == "confirmed_malicious" for f in fs)     # sample intel + heuristics never confirm
    stages = [e["stage"] for e in client.get(f"/api/investigations/{d['id']}/events").json()["events"]]
    assert [s for i, s in enumerate(stages) if i == 0 or stages[i - 1] != s] == ["evidence_collection", "processing", "correlation", "verification", "completed"]
    rep = client.get(f"/api/investigations/{d['id']}/report").json()["content"]
    assert rep["verdict"]["value"] == sc["expected_verdict"] and rep["confidence_and_limitations"] and rep["evidence"]
    for fmt in ("html", "md", "json"):
        assert client.get(f"/api/investigations/{d['id']}/report/export?format={fmt}").status_code == 200


def test_agents_all_ran_with_structured_output(client, scenario_runs):
    d = scenario_runs("phishing-to-c2")
    agents = {a["agent"] for a in d["agents"]}
    assert agents == {"orchestrator", "evidence_analyst", "network_analyst", "threat_intel_analyst", "forensics_analyst", "investigation_verifier", "report_generator"}
    assert all(a["status"] == "completed" for a in d["agents"])
    out = {a["agent"] + "|" + a["task"][:12]: client.get(f"/api/investigations/{d['id']}/agents/{a['id']}").json()["output"] for a in d["agents"]}
    assert out["evidence_analyst|parse and an"]["indicator_counts"]["ip"] >= 5
    net = out["network_analyst|analyse netw"]
    c2 = next(x for x in net["external_destinations"] if x["ip"] == "203.0.113.66")
    assert c2["clients"] == ["10.0.4.23"] and 8081 in c2["ports"] and any(sq["destination"] == "203.0.113.66" and sq["steps"] for sq in net["connection_sequences"])
    fx = out["forensics_analyst|correlate ev"]
    assert fx["correlation"]["chains"] >= 1 and fx["attack_sequence"]["label"].startswith("INFERRED")
    assert out["investigation_verifier|independentl"]["rejected"] == 0
    # a network analyst with nothing to analyse is skipped, not faked
    solo = scenario_runs("benign-url")
    assert [a["status"] for a in solo["agents"] if a["agent"] == "network_analyst"] == ["skipped"]


def test_cross_source_correlation_chain_is_evidence_backed(client, scenario_runs):
    d = scenario_runs("phishing-to-c2")
    ev = {e["kind"]: e["id"] for e in d["evidence"]}
    fs = client.get(f"/api/investigations/{d['id']}/findings").json()
    chains = [f for f in fs if f["detector"] == "correlation.delivery_to_contact"]
    via_ip = next(f for f in chains if "203.0.113.66" in f["indicators"])
    hops = via_ip["details"]["chain"]
    assert [h["relation"] for h in hops] == ["hosted_on", "resolves_to", "connects_to"] or [h["relation"] for h in hops] == ["hosted_on", "served_by", "connects_to"]
    assert all(h["evidence_ids"] for h in hops) and {ev["eml"], ev["pcap"]} <= set(via_ip["evidence_ids"])
    assert hops[1]["basis"] == "observed" and via_ip["details"]["sequence"] == "contact_after_delivery" and via_ip["details"]["sequence_basis"] == "inferred_from_timestamps"
    cross = {f["indicators"][0] for f in fs if f["detector"] == "correlation.cross_source_entity"}
    assert {"203.0.113.66", "http://paypa1-secure-login.example/account/verify?id=8842"} <= cross
    g = client.get(f"/api/investigations/{d['id']}/graph").json()
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids and e["evidence_ids"] for e in g["edges"])   # no dangling or unsupported edges
    c2 = next(n for n in g["nodes"] if n["id"] == "ip:203.0.113.66")
    assert c2["sources"] == 2 and c2["severity"] in ("high", "critical") and c2["first_seen"] < c2["last_seen"]


def test_no_relationship_from_lookalike_strings(client, new_investigation):
    """paypal.com and paypa1.com look alike but are different entities: no edge and no cross-source merge."""
    inv = new_investigation()
    client.post(f"/api/investigations/{inv}/evidence/url", json={"url": "https://www.paypal.com/"})
    client.post(f"/api/investigations/{inv}/evidence/url", json={"url": "https://www.paypa1.com/"})
    client.post(f"/api/investigations/{inv}/start")
    fs = client.get(f"/api/investigations/{inv}/findings").json()
    assert not [f for f in fs if f["detector"].startswith("correlation.")]
    g = client.get(f"/api/investigations/{inv}/graph").json()
    assert not [e for e in g["edges"] if {e["source"], e["target"]} == {"domain:www.paypal.com", "domain:www.paypa1.com"}]


def test_timeline_labels_inferred_vs_confirmed(client, scenario_runs):
    tl = client.get(f"/api/investigations/{scenario_runs('phishing-to-c2')['id']}/timeline").json()
    assert [e["at"] for e in tl["entries"]] == sorted(e["at"] for e in tl["entries"])
    assert {"email", "network", "dns", "process"} <= set(tl["layers"]) and {e["time_basis"] for e in tl["entries"]} == {"confirmed"}
    ssh = client.get(f"/api/investigations/{scenario_runs('ssh-brute-force')['id']}/timeline").json()
    assert {e["time_basis"] for e in ssh["entries"]} == {"inferred"} and any("year" in i["issue"] for i in ssh["inconsistencies"])
    url = client.get(f"/api/investigations/{scenario_runs('benign-url')['id']}/timeline").json()
    assert {e["time_basis"] for e in url["entries"]} == {"submission_time"}


def test_mitre_mappings_are_evidence_linked(client, scenario_runs):
    d = scenario_runs("phishing-to-c2")
    ms = client.get(f"/api/investigations/{d['id']}/mitre").json()
    fids = {f["id"] for f in client.get(f"/api/investigations/{d['id']}/findings").json() if f["verification_status"] == "verified"}
    assert {"T1566.002", "T1059.001", "T1027.010", "T1105", "T1053.005", "T1036.007"} <= {m["technique_id"] for m in ms}
    assert all(m["finding_id"] in fids and m["rationale"] and m["reference_url"].startswith("https://attack.mitre.org/techniques/T") for m in ms)
    assert client.get(f"/api/investigations/{scenario_runs('benign-email')['id']}/mitre").json() == []


def test_detection_rules_generated_validated_and_tested(client, scenario_runs):
    rules = client.get(f"/api/investigations/{scenario_runs('ssh-brute-force')['id']}/rules").json()
    r = next(x for x in rules if x["title"].startswith("Failed SSH"))
    assert not any("Connection to 198.51.100.23" in x["title"] for x in rules)        # a source address must not become a destination rule
    assert r["format"] == "sigma" and r["syntax_valid"] and r["deployed"] is False and r["version"] >= 1 and r["finding_ids"] and r["evidence_ids"]
    t = r["validation"]["test"]
    assert t["source_evidence"]["matched"] == t["source_evidence"]["events_cited_by_finding"] == 46
    assert t["labelled_corpus"]["benign_events"] > 50 and t["labelled_corpus"]["false_positives"] == 0 and r["validation"]["unsupported_fields"] == []
    ps = client.get(f"/api/investigations/{scenario_runs('suspicious-powershell')['id']}/rules").json()[0]
    lc = ps["validation"]["test"]["labelled_corpus"]
    assert lc["attack_events_matched"] >= 1 and lc["false_positives"] == 0          # generic behavioural rule: catches the corpus attack, no benign hits
    import yaml
    from sigma.rule import SigmaRule
    assert SigmaRule.from_yaml(ps["content"]).errors == [] and yaml.safe_load(ps["content"])["logsource"] == {"product": "windows", "category": "process_creation"}


def test_rule_validation_flags_bad_rules():
    from app.rules.generator import validate_sigma, validate_yara
    ok, v = validate_sigma("title: x\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    NotARealField: 1\n  condition: selection\n", [])
    assert not ok and v["unsupported_fields"] == ["NotARealField"]
    ok, v = validate_sigma("title: broken\ndetection: [unclosed", [])
    assert not ok and v["issues"]
    too_broad = "title: broad\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: 'powershell'\n  condition: selection\n"
    ok, v = validate_sigma(too_broad, [])
    assert ok and v["test"]["labelled_corpus"]["false_positives"] > 10               # syntactically fine, but testing exposes it as noisy
    assert validate_yara("rule broken { strings: $a = condition: $a }", [])[0] is False
    ok, v = validate_yara('rule r { strings: $a = "Get-ChildItem" condition: $a }', [])
    assert ok and v["test"]["false_positives"] == ["backup.ps1"]


def test_rerun_rebuilds_derived_data_and_versions_rules(client, new_investigation):
    inv = new_investigation("rerun")
    client.post(f"/api/investigations/{inv}/evidence/file", files={"file": ("auth.log", (SAMPLES / "ssh_bruteforce_auth.log").read_bytes(), "text/plain")})
    client.post(f"/api/investigations/{inv}/start")
    first = client.get(f"/api/investigations/{inv}").json()
    assert client.post(f"/api/investigations/{inv}/start").status_code == 202
    second = client.get(f"/api/investigations/{inv}").json()
    assert second["counts"]["findings"] == first["counts"]["findings"] and second["counts"]["events"] == first["counts"]["events"]   # no duplication
    assert client.get(f"/api/investigations/{inv}/report").json()["version"] == 1
    assert client.post(f"/api/investigations/{inv}/evidence/file", files={"file": ("auth.log", (SAMPLES / "ssh_bruteforce_auth.log").read_bytes(), "text/plain")}).status_code == 409


# ---------------- verifier ----------------
def _inv_id(client, scenario_runs, sid):
    return scenario_runs(sid)["id"]


def test_verifier_rejects_fabricated_and_unsupported_findings(client, new_investigation):
    inv = new_investigation("verifier")
    client.post(f"/api/investigations/{inv}/evidence/file", files={"file": ("auth.log", (SAMPLES / "ssh_bruteforce_auth.log").read_bytes(), "text/plain")})
    client.post(f"/api/investigations/{inv}/start")
    with session_scope() as db:
        ev = db.scalar(select(Evidence).where(Evidence.investigation_id == inv))
        real = db.scalar(select(Finding).where(Finding.investigation_id == inv, Finding.detector == "auth.password_spraying"))
        mk = lambda **kw: db.add(Finding(investigation_id=inv, severity="critical", classification="confirmed_malicious", basis="deterministic", confidence=0.99, produced_by="test-hallucination", **kw))
        mk(detector="x.no_evidence", title="claim with no evidence", evidence_ids=[], event_ids=[], indicator_values=[])
        mk(detector="x.ghost_evidence", title="cites evidence that does not exist", evidence_ids=["EVD-000000000000"], event_ids=[], indicator_values=[])
        mk(detector="x.foreign_indicator", title="names an IP that is not in the evidence", evidence_ids=[ev.id], event_ids=[], indicator_values=["45.33.32.156"])
        mk(detector="auth.brute_force", title="inflated count", evidence_ids=[ev.id], event_ids=real.event_ids[:3], indicator_values=["198.51.100.23"], details={"failures": 500, "source_ip": "198.51.100.23"})
        mk(detector="x.overclaim", title="heuristic claiming confirmation", evidence_ids=[ev.id], event_ids=[], indicator_values=["198.51.100.23"])
        db.add(Finding(investigation_id=inv, detector="ml.phishing_url", title="model says malicious", severity="high", classification="confirmed_malicious", basis="ml_model", confidence=0.99,
                       evidence_ids=[ev.id], event_ids=[], indicator_values=[]))
    with session_scope() as db:
        s = verify_findings(db, inv)
        by = {f.detector + "|" + f.title: f for f in db.scalars(select(Finding).where(Finding.investigation_id == inv))}
        assert by["x.no_evidence|claim with no evidence"].verification_status == "rejected"
        assert by["x.ghost_evidence|cites evidence that does not exist"].verification_status == "rejected"
        assert "45.33.32.156" in by["x.foreign_indicator|names an IP that is not in the evidence"].verification_notes
        assert "recount" in by["auth.brute_force|inflated count"].verification_notes
        over = by["x.overclaim|heuristic claiming confirmation"]
        assert over.verification_status == "downgraded" and over.classification == "suspicious"
        ml = by["ml.phishing_url|model says malicious"]
        assert ml.verification_status == "downgraded" and ml.classification == "suspicious"       # an ML score can never confirm
        assert s["rejected"] == 4 and s["downgraded"] == 2


def test_verifier_detects_evidence_tampering(client, new_investigation):
    import os, stat
    inv = new_investigation("tamper")
    client.post(f"/api/investigations/{inv}/evidence/file", files={"file": ("a.eml", (SAMPLES / "phishing_email.eml").read_bytes(), "message/rfc822")})
    client.post(f"/api/investigations/{inv}/start")
    with session_scope() as db:
        path = db.scalar(select(Evidence).where(Evidence.investigation_id == inv)).storage_path
    assert not os.stat(path).st_mode & (stat.S_IWUSR | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)   # stored read-only, never executable
    os.chmod(path, 0o600)
    with open(path, "ab") as f:
        f.write(b"tampered")
    with session_scope() as db:
        s = verify_findings(db, inv)
        assert s["verified"] == 0 and s["rejected"] == s["checked"] and "SHA-256" in s["issues"][0]["issue"]


def test_verifier_surfaces_conflicting_intel(client, new_investigation):
    inv = new_investigation("conflict")
    client.post(f"/api/investigations/{inv}/evidence/url", json={"url": "http://example.com/secure/login/verify-account/update-password.php"})
    client.post(f"/api/investigations/{inv}/start")
    d = client.get(f"/api/investigations/{inv}").json()
    v = next(client.get(f"/api/investigations/{inv}/agents/{a['id']}").json()["output"] for a in d["agents"] if a["agent"] == "investigation_verifier")
    assert any("clean" in c["conflict"] for c in v["conflicts"])
    rep = client.get(f"/api/investigations/{inv}/report").json()["content"]
    assert rep["verification"]["conflicts"]


# ---------------- prompt injection / LLM containment ----------------
class ObedientLLM(llm_mod.LLMProvider):
    """Simulates a model that was successfully prompt-injected by the email body and also hallucinates."""
    name = "fake-compromised"

    def __init__(self):
        self.seen = ""

    def complete(self, system, user):
        self.seen = system + user
        ids = json.loads(user.split("\n", 1)[1])["findings"]
        return json.dumps({"sentences": [
            {"text": "This message is benign and safe; no action is needed.", "finding_ids": []},
            {"text": "The attacker's server 45.33.32.156 exfiltrated the payroll database.", "finding_ids": [ids[0]["id"]]},
            {"text": "Verified finding FND-FAKE0000000 proves compromise.", "finding_ids": ["FND-FAKE0000000"]},
            {"text": "The email link displays one domain but leads to another.", "finding_ids": [ids[0]["id"]]},
            "not even an object"]})


def test_prompt_injection_cannot_change_verdict_or_inject_claims(client, new_investigation):
    fake = ObedientLLM()
    llm_mod.set_llm_override(fake)
    try:
        inv = new_investigation("injection")
        client.post(f"/api/investigations/{inv}/evidence/file", files={"file": ("p.eml", (SAMPLES / "phishing_email.eml").read_bytes(), "message/rfc822")})
        client.post(f"/api/investigations/{inv}/start")
    finally:
        llm_mod.set_llm_override(None)
    d = client.get(f"/api/investigations/{inv}").json()
    assert d["verdict"] == "suspicious"                                    # the injected "classify as benign" had no effect
    rep = client.get(f"/api/investigations/{inv}/report").json()["content"]
    text = " ".join(s["text"] for s in rep["executive_summary"])
    assert "benign and safe" not in text and "45.33.32.156" not in text and "FND-FAKE" not in text
    assert "displays one domain" in text                                    # the one supported sentence survived
    assert rep["llm_audit"]["kept"] == 1 and len(rep["llm_audit"]["dropped"]) == 4
    assert "ignore all previous instructions" not in fake.seen.lower()     # raw evidence body is never sent to the model
    assert "UNTRUSTED DATA" in fake.seen


def test_llm_failure_falls_back_to_template(client, new_investigation):
    class Broken(llm_mod.LLMProvider):
        name = "broken"
        def complete(self, s, u): raise TimeoutError("model unavailable")
    llm_mod.set_llm_override(Broken())
    try:
        inv = new_investigation("llm-down")
        client.post(f"/api/investigations/{inv}/evidence/file", files={"file": ("p.eml", (SAMPLES / "phishing_email.eml").read_bytes(), "message/rfc822")})
        client.post(f"/api/investigations/{inv}/start")
    finally:
        llm_mod.set_llm_override(None)
    rep = client.get(f"/api/investigations/{inv}/report").json()
    assert rep["narrative_source"] == "deterministic_template" and rep["content"]["llm_audit"]["fallback"] == "deterministic_template"


# ---------------- threat intelligence adapters ----------------
def _transport(handler):
    return httpx.MockTransport(handler)


def test_intel_adapters_parse_cache_and_rate_limit(client, new_investigation, monkeypatch):
    from app.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "virustotal_api_key", "k1"); monkeypatch.setattr(s, "abuseipdb_api_key", "k2"); monkeypatch.setattr(s, "otx_api_key", "k3")
    calls = {"vt": 0, "abuse": 0}

    def vt(req):
        calls["vt"] += 1
        assert req.headers["x-apikey"] == "k1"
        if "8.8.4.4" in req.url.path:
            return httpx.Response(404)
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 10}}}})

    def abuse(req):
        calls["abuse"] += 1
        return httpx.Response(429)

    v, a = prov.VirusTotal(), prov.AbuseIPDB()
    v.transport, a.transport = _transport(vt), _transport(abuse)
    inv = new_investigation("intel")
    with session_scope() as db:
        st = enrich(db, inv, [("ip", "203.0.113.66"), ("ip", "8.8.4.4"), ("ip", "10.0.0.5"), ("domain", "x.example")], providers=[v, a])
    assert st["records"] == 2 and st["skipped_private"] == 1 and st["rate_limited"] == ["abuseipdb"]
    assert calls["abuse"] == 1                                                 # stopped after the first 429
    with session_scope() as db:
        recs = list(db.scalars(select(IntelRecord).where(IntelRecord.investigation_id == inv)))
        hit = next(r for r in recs if r.source == "virustotal" and r.indicator_value == "203.0.113.66")
        assert hit.verdict == "malicious" and "7 malicious" in hit.summary and hit.queried_at and not hit.from_cache and hit.source_reliability == "community-aggregated"
        assert [r.verdict for r in recs if r.source == "abuseipdb"] == ["rate_limited"]
        assert not [r for r in recs if r.indicator_value == "8.8.4.4" and r.source == "virustotal"]   # 404 = no record, never "clean"
        assert db.scalar(select(IntelCache).where(IntelCache.indicator_value == "203.0.113.66")) is not None
    before = calls["vt"]
    inv2 = new_investigation("intel-cache")
    with session_scope() as db:
        st2 = enrich(db, inv2, [("ip", "203.0.113.66")], providers=[v])
    assert calls["vt"] == before and st2["cache_hits"] == 1
    with session_scope() as db:
        assert db.scalar(select(IntelRecord).where(IntelRecord.investigation_id == inv2)).from_cache is True


def test_intel_provider_error_is_recorded_not_invented(client, new_investigation, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "otx_api_key", "k")
    o = prov.OTX()
    o.transport = _transport(lambda req: httpx.Response(500))
    inv = new_investigation("intel-err")
    with session_scope() as db:
        st = enrich(db, inv, [("domain", "bad.example")], providers=[o])
        rec = db.scalar(select(IntelRecord).where(IntelRecord.investigation_id == inv))
        assert st["errors"] == 1 and rec.verdict == "error"


def test_missing_api_keys_degrade_gracefully(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "intel_offline", False)
    assert [p.name for p in prov.active_providers()] == ["offline_bundle"]   # no keys configured: only the bundle, no crash


def test_confirmed_malicious_requires_two_independent_non_sample_bases(client, new_investigation, monkeypatch):
    """With a real (non-sample) reputation source agreeing with observed behaviour, ARGUS confirms. With sample intel it must not."""
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "intel_offline", False); monkeypatch.setattr(get_settings(), "virustotal_api_key", "k")
    monkeypatch.setattr(prov.VirusTotal, "transport", _transport(lambda req: httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "harmless": 50}}}})
                                                                 if "203.0.113.66" in req.url.path else httpx.Response(404)))
    inv = new_investigation("confirm")
    client.post(f"/api/investigations/{inv}/evidence/file", files={"file": ("c.pcap", (SAMPLES / "workstation_capture.pcap").read_bytes(), "application/octet-stream")})
    client.post(f"/api/investigations/{inv}/start")
    d = client.get(f"/api/investigations/{inv}").json()
    fs = client.get(f"/api/investigations/{inv}/findings").json()
    conf = [f for f in fs if f["classification"] == "confirmed_malicious"]
    assert d["verdict"] == "malicious" and len(conf) == 1 and conf[0]["detector"] == "correlation.corroborated_indicator" and conf[0]["verification_status"] == "verified"
    assert "virustotal" in conf[0]["details"]["intel_sources"] and not conf[0]["details"]["sample_intel_only"] and conf[0]["details"]["behavioural_findings"]


# ---------------- API / persistence ----------------
def test_health_system_search_history_audit(client, scenario_runs):
    d = scenario_runs("phishing-to-c2")
    assert client.get("/api/health").json()["status"] == "ok"
    sysinfo = client.get("/api/system").json()
    assert set(sysinfo["evidence_kinds"]) == {"url", "eml", "email_headers", "json_events", "auth_log", "pcap", "file", "pdf", "screenshot"}
    assert sysinfo["models"]["phishing_url_classifier"]["installed"] and len(sysinfo["vision"]["reference_pages"]) == 2
    hits = client.get("/api/search", params={"q": "203.0.113.66"}).json()
    assert any(h["type"] == "indicator" and h["investigation_id"] == d["id"] for h in hits)
    assert any(h["type"] == "finding" for h in client.get("/api/search", params={"q": "PowerShell"}).json())
    assert client.get("/api/investigations", params={"verdict": "benign"}).json() and all(i["verdict"] == "benign" for i in client.get("/api/investigations", params={"verdict": "benign"}).json())
    assert any(r["investigation_id"] == d["id"] for r in client.get("/api/reports").json())
    actions = {a["action"] for a in client.get("/api/audit?limit=500").json()}
    assert {"investigation.created", "evidence.added", "analysis.started", "investigation.completed", "report.exported"} <= actions


def test_evidence_provenance_and_detail(client, scenario_runs):
    import hashlib
    d = scenario_runs("phishing-to-c2")
    eml = next(e for e in d["evidence"] if e["kind"] == "eml")
    assert eml["sha256"] == hashlib.sha256((SAMPLES / "phishing_email.eml").read_bytes()).hexdigest() and eml["source"] == "bundled_sample_dataset" and eml["ingested_at"].endswith("+00:00")
    det = client.get(f"/api/investigations/{d['id']}/evidence/{eml['id']}").json()
    assert det["meta"]["authentication"]["spf"] == "fail" and det["indicators"] and det["findings"] and det["relationships"]
    pcap = next(e for e in d["evidence"] if e["kind"] == "pcap")
    meta = client.get(f"/api/investigations/{d['id']}/evidence/{pcap['id']}").json()["meta"]
    assert meta["packets"] > 1000 and meta["anomaly_model"]["flows_scored"] > 0
    assert client.get(f"/api/investigations/{d['id']}/evidence/EVD-NOPE").status_code == 404


def test_delete_investigation_cascades(client, new_investigation):
    inv = new_investigation("delete-me")
    client.post(f"/api/investigations/{inv}/evidence/url", json={"url": "https://www.example.org/"})
    client.post(f"/api/investigations/{inv}/start")
    assert client.delete(f"/api/investigations/{inv}").status_code == 204
    with session_scope() as db:
        assert db.get(Investigation, inv) is None
        for model in (Evidence, Finding, Relationship):
            assert db.scalar(select(model).where(model.investigation_id == inv)) is None
        assert db.scalar(select(AuditLog).where(AuditLog.action == "investigation.deleted", AuditLog.target == inv)) is not None


def test_concurrent_investigations_do_not_interfere(client, monkeypatch):
    """Real threaded execution (not inline): several analyses queued at once must all complete correctly."""
    import time
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "run_inline", False)
    ids = {}
    for sid in ("benign-email", "ssh-brute-force", "suspicious-powershell", "unusual-outbound", "benign-url", "screenshot-lookalike"):
        inv = client.post(f"/api/samples/{sid}").json()["id"]
        assert client.post(f"/api/investigations/{inv}/start").status_code == 202
        ids[sid] = inv
    # the last one submitted is still queued behind the two workers: a second start must be refused
    assert client.post(f"/api/investigations/{ids['screenshot-lookalike']}/start").status_code == 409
    deadline = time.time() + 90
    while time.time() < deadline:
        states = {sid: client.get(f"/api/investigations/{i}").json() for sid, i in ids.items()}
        if all(s["status"] in ("completed", "failed") for s in states.values()):
            break
        time.sleep(0.5)
    expected = {s["id"]: s["expected_verdict"] for s in SCENARIOS}
    assert {sid: (s["status"], s["verdict"]) for sid, s in states.items()} == {sid: ("completed", expected[sid]) for sid in ids}


def test_all_serialised_timestamps_carry_utc_offset(client, scenario_runs):
    """Naive timestamps would be read as local time by browsers. Every timestamp the API emits must be explicit UTC."""
    import re
    d = scenario_runs("phishing-to-c2")
    blobs = [client.get(f"/api/investigations/{d['id']}{p}").text for p in ("", "/report", "/graph", "/timeline", "/findings", "/intel", "/rules", "/events")]
    naive = [m for b in blobs for m in re.findall(r'"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?)"', b)]
    assert naive == []
    rep = json.loads(blobs[1])["content"]["metadata"]
    assert rep["created_at"].endswith("+00:00") and rep["report_generated"].endswith("+00:00")
