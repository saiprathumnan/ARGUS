"""Static file analysis. Files are read as bytes only: nothing is ever executed, opened with a handler,
unpacked or rendered."""
import hashlib
import math
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache

from ..config import get_settings
from .ioc import extract_iocs

STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")
WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
SUSPICIOUS_STRINGS = [
    (rb"powershell(\.exe)?\s+-", "powershell_invocation"), (rb"cmd(\.exe)?\s+/c", "cmd_invocation"), (rb"CurrentVersion\\Run", "run_key_persistence"),
    (rb"(VirtualAlloc|WriteProcessMemory|CreateRemoteThread)", "process_injection_api"), (rb"(IsDebuggerPresent|CheckRemoteDebuggerPresent)", "anti_debug_api"),
    (rb"schtasks\s+/create", "scheduled_task"), (rb"(wscript|cscript)\.shell", "script_host"), (rb"vssadmin.{0,20}delete", "shadow_copy_deletion"),
    (rb"[A-Za-z0-9+/]{200,}={0,2}", "long_base64_blob"), (rb"(mimikatz|sekurlsa::|lsadump::)", "credential_dumping_tool_string"),
]
PDF_KEYS = [b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile", b"/URI", b"/AcroForm", b"/XFA", b"/ObjStm", b"/Encrypt"]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


@lru_cache
def _yara_rules():
    import yara
    d = get_settings().data_dir / "yara"
    files = {p.stem: str(p) for p in sorted(d.glob("*.yar"))}
    return yara.compile(filepaths=files) if files else None


def yara_scan(data: bytes) -> list[dict]:
    rules = _yara_rules()
    if rules is None:
        return []
    out = []
    for m in rules.match(data=data, timeout=20):
        strings = []
        for s in m.strings[:10]:
            for inst in s.instances[:3]:
                strings.append({"id": s.identifier, "offset": inst.offset, "data": inst.matched_data[:60].decode("latin-1")})
        out.append({"rule": m.rule, "namespace": m.namespace, "meta": dict(m.meta), "strings": strings[:12]})
    return out


def pe_header(data: bytes) -> dict | None:
    try:
        if data[:2] != b"MZ":
            return None
        off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[off:off + 4] != b"PE\x00\x00":
            return None
        machine, nsec, tstamp = struct.unpack_from("<HHI", data, off + 4)
        chars = struct.unpack_from("<H", data, off + 22)[0]
        return {"machine": {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}.get(machine, hex(machine)), "sections": nsec,
                "compile_time": datetime.fromtimestamp(tstamp, tz=timezone.utc).isoformat() if 0 < tstamp < 4102444800 else None, "is_dll": bool(chars & 0x2000)}
    except (struct.error, IndexError, OverflowError, OSError):
        return None


def analyse_file(data: bytes, filename: str, mime: str) -> dict:
    strings = [m.group(0).decode("ascii") for m in STRING_RE.finditer(data[:5_000_000])][:20000]
    strings += [m.group(0).decode("utf-16-le", "ignore") for m in WIDE_RE.finditer(data[:5_000_000])][:5000]
    blob = "\n".join(strings)
    sus = []
    for rx, name in SUSPICIOUS_STRINGS:
        m = re.search(rx, data[:5_000_000], re.I)
        if m:
            sus.append({"id": name, "offset": m.start(), "sample": m.group(0)[:80].decode("latin-1")})
    res = {"sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(), "size": len(data), "mime": mime,
           "entropy": round(entropy(data[:5_000_000]), 3), "string_count": len(strings), "suspicious_strings": sus, "iocs": extract_iocs(blob[:2_000_000]),
           "yara": yara_scan(data), "pe": pe_header(data)}
    if data[:5] == b"%PDF-":
        res["pdf"] = {k.decode(): data.count(k) for k in PDF_KEYS if data.count(k)}
        res["pdf"]["version"] = data[5:8].decode("latin-1", "ignore")
        uris = re.findall(rb"/URI\s*\(([^)]{4,300})\)", data)
        for u in uris[:50]:
            s = u.decode("latin-1")
            if s not in res["iocs"]["url"] and s.lower().startswith(("http://", "https://")):
                res["iocs"]["url"].append(s)
    parts = filename.lower().split(".")
    res["double_extension"] = len(parts) >= 3 and parts[-1] in {"exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "hta", "lnk", "jar"} and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}
    return res


def detect_file(a: dict, filename: str) -> list[dict]:
    out = []
    for m in a["yara"]:
        cls = str(m["meta"].get("argus_class", "suspicious"))
        classification, severity, conf = {"malicious": ("confirmed_malicious", "critical", 0.95), "test_fixture": ("benign", "info", 0.99)}.get(cls, ("suspicious", "high", 0.75))
        out.append({"detector": "file.yara_match", "severity": severity, "confidence": conf, "classification": classification, "basis": "signature",
                    "title": f"YARA rule {m['rule']} matched {filename}" + (" (engine self-test fixture, harmless)" if cls == "test_fixture" else ""),
                    "description": f"{m['meta'].get('description', 'No description')}. Matched {len(m['strings'])} string instance(s); rule class '{cls}'.",
                    "indicators": [a["sha256"]], "details": {"rule": m["rule"], "rule_class": cls, "strings": m["strings"], "rule_file": m["namespace"]}})
    if a.get("double_extension"):
        out.append({"detector": "file.double_extension", "severity": "high", "confidence": 0.8, "classification": "suspicious", "basis": "deterministic",
                    "title": f"Filename disguises an executable type: {filename}", "description": "The filename ends in a document-style extension followed by an executable extension.",
                    "indicators": [a["sha256"]], "details": {"filename": filename}})
    ids = {s["id"] for s in a["suspicious_strings"]}
    strong = ids & {"process_injection_api", "credential_dumping_tool_string", "shadow_copy_deletion", "run_key_persistence"}
    if len(ids) >= 2 or strong:
        out.append({"detector": "file.suspicious_strings", "severity": "medium", "confidence": 0.5, "classification": "suspicious", "basis": "deterministic",
                    "title": f"Suspicious embedded strings in {filename}: {', '.join(sorted(ids))}",
                    "description": "Static string extraction found content associated with malicious tooling. Strings indicate capability, not behaviour; legitimate admin and security tools contain the same strings.",
                    "indicators": [a["sha256"]], "details": {"strings": a["suspicious_strings"]}})
    if a["entropy"] >= 7.5 and a["size"] > 20_000 and a["mime"] in ("application/x-dosexec", "application/x-elf", "application/octet-stream"):
        out.append({"detector": "file.high_entropy", "severity": "low", "confidence": 0.35, "classification": "insufficient_evidence", "basis": "deterministic",
                    "title": f"High byte entropy ({a['entropy']}) in {filename}", "description": "Entropy near 8 bits/byte indicates compression or encryption (packers produce this; so do installers and media).",
                    "indicators": [a["sha256"]], "details": {"entropy": a["entropy"]}})
    pdf = a.get("pdf") or {}
    if (pdf.get("/JavaScript") or pdf.get("/JS")) and not any(m["rule"] == "ARGUS_PDF_AutoAction_JavaScript" for m in a["yara"]):
        out.append({"detector": "file.pdf_javascript", "severity": "low", "confidence": 0.4, "classification": "insufficient_evidence", "basis": "deterministic",
                    "title": f"PDF contains JavaScript objects: {filename}", "description": "JavaScript in a PDF is uncommon in ordinary documents but is also used by interactive forms.",
                    "indicators": [a["sha256"]], "details": {"pdf_keywords": pdf}})
    return out
