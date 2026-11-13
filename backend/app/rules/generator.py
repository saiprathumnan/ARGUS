"""Detection rule generation from VERIFIED findings, with validation and testing.

Pipeline per rule: generate -> YAML/YARA syntax validation (pySigma / yara-python) -> unsupported-field check
-> run against (a) the events the finding cites and (b) a labelled corpus -> store as a new version.
ARGUS never deploys rules: `deployed` stays False and there is no code path that sets it.
"""
import json
import re
import uuid
from functools import lru_cache
from pathlib import Path

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..analysis import logs as logs_an
from ..config import get_settings
from ..models import DetectionRule, Evidence, Finding, SecurityEvent
from ..security.uploads import read_original
from .sigma_eval import LOGSOURCE_FIELDS, logsource_key, rule_matches, used_fields


def _event_dict(e) -> dict:
    return {"category": e.category, "action": e.action, "outcome": e.outcome, "src_ip": e.src_ip, "dst_ip": e.dst_ip, "dst_port": e.dst_port, "domain": e.domain, "url": e.url,
            "user": e.user, "host": e.host, "summary": e.summary or "", "data": e.data or {}}


@lru_cache
def labelled_corpus() -> list[dict]:
    """[{event, label, source}] from data/samples/labelled. label is 'attack' or 'benign'."""
    d = get_settings().data_dir / "samples" / "labelled"
    out = []
    p = d / "events.jsonl"
    if p.exists():
        for i, line in enumerate(p.read_text().splitlines()):
            if line.strip():
                rec = json.loads(line)
                ev = logs_an.normalise_json_event(rec, i)
                if ev:
                    out.append({"event": _event_dict(ev), "label": rec.get("argus_label", "benign"), "source": "events.jsonl"})
    for name, label in (("benign_auth.log", "benign"), ("attack_auth.log", "attack")):
        p = d / name
        if p.exists():
            evs, _ = logs_an.parse_auth_log(p.read_text(), 2026)
            out += [{"event": _event_dict(e), "label": label, "source": name} for e in evs]
    return out


def _sigma(title, description, logsource, detection, level, tags, finding: Finding, falsepositives) -> str:
    doc = {"title": title, "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"argus:{finding.investigation_id}:{finding.detector}:{json.dumps(detection, sort_keys=True)}")),
           "status": "experimental", "description": description, "references": [f"argus://investigations/{finding.investigation_id}/findings/{finding.id}"],
           "author": "ARGUS (generated; review before use)", "date": finding.created_at.strftime("%Y-%m-%d"), "tags": tags, "logsource": logsource, "detection": detection,
           "falsepositives": falsepositives, "level": level}
    return yaml.safe_dump(doc, sort_keys=False, width=120, allow_unicode=True)


def _drafts_for(f: Finding, events: list[SecurityEvent]) -> list[dict]:
    d = f.details or {}
    out = []
    win = any((e.data or {}).get("event_id") for e in events)
    if f.detector in ("auth.brute_force", "auth.password_spraying", "auth.success_after_failures"):
        src = d.get("source_ip")
        tag = "attack.t1110.003" if f.detector == "auth.password_spraying" else "attack.t1110.001"
        if not src:
            return out
        if win:
            out.append({"key": f"sigma:auth_fail:{src}", "format": "sigma", "title": f"Failed Windows logons from {src}",
                        "content": _sigma(f"Failed Logons From Brute-Force Source {src}", f"Detects failed logons (4625) from {src}, observed performing {d.get('failures', 'repeated')} failed authentications.",
                                          {"product": "windows", "service": "security"}, {"selection": {"EventID": 4625, "IpAddress": src}, "condition": "selection"}, "medium",
                                          ["attack.credential-access", tag], f, ["Legitimate user at this address mistyping a password"])})
        else:
            out.append({"key": f"sigma:ssh_fail:{src}", "format": "sigma", "title": f"Failed SSH logins from {src}",
                        "content": _sigma(f"Failed SSH Logins From Brute-Force Source {src}", f"Detects failed SSH authentication from {src}, observed performing {d.get('failures', 'repeated')} failed logins.",
                                          {"product": "linux", "service": "sshd"}, {"selection": {"|all": ["Failed password", f"from {src} "]}, "condition": "selection"}, "medium",
                                          ["attack.credential-access", tag], f, ["Legitimate user at this address mistyping a password"])})
    elif f.detector == "process.suspicious_powershell":
        matched = set(d.get("matched", []))
        sel = {"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"]}
        parts = {}
        if "encoded_command" in matched:
            parts["selection_enc"] = {"CommandLine|contains": [" -enc ", " -EncodedCommand ", " -ec ", " -e "]}
        if "hidden_window" in matched:
            parts["selection_hidden"] = {"CommandLine|contains": ["-w hidden", "-windowstyle hidden", "-w h "]}
        if "download_cradle" in matched:
            parts["selection_dl"] = {"CommandLine|contains": ["DownloadString", "DownloadFile", "Invoke-WebRequest", "Net.WebClient", "Start-BitsTransfer"]}
        if "execution_policy_bypass" in matched:
            parts["selection_bypass"] = {"CommandLine|contains": ["-ep bypass", "-executionpolicy bypass"]}
        if parts:
            det = {"selection_img": sel, **parts, "condition": "selection_img and " + " and ".join(parts)}
            out.append({"key": "sigma:ps:" + "+".join(sorted(parts)), "format": "sigma", "title": "PowerShell with " + ", ".join(k.split("_", 1)[1] for k in parts),
                        "content": _sigma("Suspicious PowerShell Launch Options (" + ", ".join(k.split("_", 1)[1] for k in sorted(parts)) + ")",
                                          "Detects PowerShell started with the option combination observed in this investigation.", {"product": "windows", "category": "process_creation"},
                                          det, "high" if len(parts) >= 2 else "medium", ["attack.execution", "attack.t1059.001"], f, ["Administrative scripts and software deployment tools that use encoded or hidden PowerShell"])})
    elif f.detector.startswith("process.lolbin_"):
        b = d.get("binary")
        pat = {"certutil": ["-urlcache", "-decode"], "mshta": ["http", "javascript:", "vbscript:"], "regsvr32": ["/i:http", "scrobj.dll"], "bitsadmin": ["/transfer"],
               "wmic": ["process call create"], "schtasks": ["/create"], "vssadmin": ["delete shadows"], "rundll32": ["javascript:"]}.get(b)
        if pat:
            out.append({"key": f"sigma:lolbin:{b}", "format": "sigma", "title": f"{b} suspicious usage",
                        "content": _sigma(f"Suspicious {b} Usage", f"Detects {b} used with the argument pattern observed in this investigation.", {"product": "windows", "category": "process_creation"},
                                          {"selection": {"Image|endswith": f"\\{b}.exe", "CommandLine|contains": pat}, "condition": "selection"}, "medium", ["attack.defense-evasion"], f,
                                          ["Legitimate administrative use of this binary"])})
    elif f.detector in ("network.beaconing", "network.suspicious_port", "correlation.corroborated_indicator", "correlation.delivery_to_contact"):
        ips = [v for v in f.indicator_values if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", str(v)) and not str(v).startswith(("10.", "192.168.", "127."))
               and not re.match(r"172\.(1[6-9]|2\d|3[01])\.", str(v))]
        doms = [v for v in f.indicator_values if re.fullmatch(r"([a-z0-9\-]+\.)+[a-z][a-z0-9\-]+", str(v))]
        for ip in ips[:2]:
            if events and not any(e.dst_ip == ip for e in events):
                continue  # the address only ever appears as a SOURCE in the cited events: a destination rule would be wrong
            sel = {"dst_ip": ip}
            if d.get("port"):
                sel["dst_port"] = d["port"]
            out.append({"key": f"sigma:net_dst:{ip}:{d.get('port', '')}", "format": "sigma", "title": f"Connection to {ip}" + (f":{d['port']}" if d.get("port") else ""),
                        "content": _sigma(f"Network Connection To Investigated Destination {ip}", f"Detects connections to {ip}, identified in this investigation ({f.title[:100]}).",
                                          {"category": "firewall"}, {"selection": sel, "condition": "selection"}, "high", ["attack.command-and-control"], f,
                                          ["Address reassigned to a legitimate service (IP indicators age quickly)"])})
        for dom in doms[:2]:
            out.append({"key": f"sigma:dns:{dom}", "format": "sigma", "title": f"DNS query for {dom}",
                        "content": _sigma(f"DNS Query For Investigated Domain {dom}", f"Detects DNS queries for {dom} or its subdomains, identified in this investigation.",
                                          {"category": "dns"}, {"selection": {"query|endswith": dom}, "condition": "selection"}, "high", ["attack.command-and-control"], f,
                                          ["Domain re-registered by a legitimate owner"])})
    elif f.detector == "network.dns_tunneling_pattern" and d.get("parent_domain"):
        dom = d["parent_domain"]
        out.append({"key": f"sigma:dns:{dom}", "format": "sigma", "title": f"DNS query under {dom}",
                    "content": _sigma(f"DNS Queries Under Suspected Tunnelling Domain {dom}", f"Detects DNS queries for subdomains of {dom}.", {"category": "dns"},
                                      {"selection": {"query|endswith": "." + dom}, "condition": "selection"}, "high", ["attack.command-and-control", "attack.t1071.004"], f, ["Legitimate service using this parent domain"])})
    elif f.detector == "file.suspicious_strings" and d.get("strings"):
        strs = [s["sample"] for s in d["strings"] if s["id"] != "long_base64_blob" and 6 <= len(s["sample"]) <= 80][:6]
        if len(strs) >= 2:
            name = "ARGUS_Gen_" + re.sub(r"[^A-Za-z0-9]", "_", f.id)
            lines = "\n".join(f'        $s{i} = "{s.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}" ascii wide nocase' for i, s in enumerate(strs))
            content = (f"rule {name}\n{{\n    meta:\n        description = \"Generated from ARGUS finding {f.id}: strings observed together in one file\"\n        author = \"ARGUS (generated; review before use)\"\n"
                       f"        argus_class = \"suspicious\"\n        reference = \"argus://investigations/{f.investigation_id}/findings/{f.id}\"\n    strings:\n{lines}\n    condition:\n        {max(2, len(strs) - 1)} of them\n}}\n")
            out.append({"key": f"yara:strings:{f.indicator_values[0] if f.indicator_values else f.id}", "format": "yara", "title": f"YARA: string combination from {f.title[:60]}", "content": content})
    return out


def validate_sigma(content: str, source_events: list[dict]) -> tuple[bool, dict]:
    v: dict = {"issues": [], "unsupported_fields": []}
    try:
        doc = yaml.safe_load(content)
        from sigma.rule import SigmaRule
        rule = SigmaRule.from_yaml(content)
        if rule.errors:
            v["issues"] += [str(e) for e in rule.errors]
        try:
            from sigma.validation import SigmaValidator
            from sigma.validators.core import validators as core_validators
            issues = SigmaValidator([cls for cls in core_validators.values()]).validate_rule(rule)
            v["pysigma_validator_issues"] = [f"{type(i).__name__}: {getattr(i, 'description', '')}"[:200] for i in issues][:20]
        except Exception as e:  # validator set differs between pySigma versions; syntax result above still stands
            v["pysigma_validator_issues"] = [f"validators unavailable: {type(e).__name__}"]
    except Exception as e:
        v["issues"].append(f"{type(e).__name__}: {e}"[:300])
        return False, v
    key = logsource_key(doc.get("logsource", {}))
    allowed = LOGSOURCE_FIELDS.get(key)
    if allowed is None:
        v["issues"].append(f"logsource {key} is not in ARGUS's field taxonomy; field check skipped")
    else:
        v["unsupported_fields"] = sorted(used_fields(doc) - allowed)
    v["syntax"] = "pySigma parsed the rule without errors" if not v["issues"] else "see issues"
    # --- testing ---
    hits_src = sum(1 for e in source_events if rule_matches(doc, e))
    corpus = labelled_corpus()
    benign = [c for c in corpus if c["label"] == "benign"]
    attack = [c for c in corpus if c["label"] == "attack"]
    fp = sum(1 for c in benign if rule_matches(doc, c["event"]))
    tp_corpus = sum(1 for c in attack if rule_matches(doc, c["event"]))
    v["test"] = {"source_evidence": {"events_cited_by_finding": len(source_events), "matched": hits_src,
                                     "note": "Events cited by the finding are the ground-truth positives for this rule."},
                 "labelled_corpus": {"benign_events": len(benign), "false_positives": fp, "attack_events": len(attack), "attack_events_matched": tp_corpus,
                                     "note": "IOC-specific rules are not expected to match unrelated attack events; false positives on the benign set are the meaningful number."},
                 "evaluator": "ARGUS built-in Sigma subset evaluator over normalised events (not a SIEM backend)"}
    ok = not v["issues"] or all("not in ARGUS's field taxonomy" in i for i in v["issues"])
    return ok and not v["unsupported_fields"], v


def validate_yara(content: str, source_files: list[bytes]) -> tuple[bool, dict]:
    import yara
    v: dict = {"issues": []}
    try:
        rules = yara.compile(source=content)
    except yara.Error as e:
        v["issues"].append(str(e)[:300])
        return False, v
    v["syntax"] = "yara-python compiled the rule"
    d = get_settings().data_dir / "samples" / "benign_files"
    benign = sorted(p for p in d.glob("*") if p.is_file()) if d.exists() else []
    fp = [p.name for p in benign if rules.match(data=p.read_bytes())]
    v["test"] = {"source_files": len(source_files), "source_files_matched": sum(1 for b in source_files if rules.match(data=b)), "benign_files": len(benign), "false_positives": fp}
    return True, v


def generate_rules(db: Session, inv: str) -> list[DetectionRule]:
    created = []
    findings = [f for f in db.scalars(select(Finding).where(Finding.investigation_id == inv))
                if f.verification_status == "verified" and f.classification in ("suspicious", "confirmed_malicious")]
    seen_keys = set()
    for f in findings:
        events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(f.event_ids)))) if f.event_ids else []
        for draft in _drafts_for(f, events):
            if draft["key"] in seen_keys:
                continue
            seen_keys.add(draft["key"])
            if draft["format"] == "sigma":
                ok, validation = validate_sigma(draft["content"], [_event_dict(e) for e in events])
            else:
                files = [read_original(e.storage_path) for e in db.scalars(select(Evidence).where(Evidence.id.in_(f.evidence_ids))) if e.kind in ("file", "pdf")]
                ok, validation = validate_yara(draft["content"], files)
            prev = db.scalar(select(DetectionRule).where(DetectionRule.rule_key == draft["key"]).order_by(DetectionRule.version.desc()))
            if prev and prev.investigation_id == inv and yaml.safe_load(prev.content) == yaml.safe_load(draft["content"]) if draft["format"] == "sigma" and prev else False:
                continue
            version = (db.scalar(select(func.max(DetectionRule.version)).where(DetectionRule.rule_key == draft["key"])) or 0) + 1
            rule = DetectionRule(investigation_id=inv, rule_key=draft["key"], version=version, format=draft["format"], title=draft["title"][:300], content=draft["content"],
                                 finding_ids=[f.id], evidence_ids=f.evidence_ids, syntax_valid=ok, validation=validation, deployed=False)
            db.add(rule)
            created.append(rule)
    db.flush()
    return created
