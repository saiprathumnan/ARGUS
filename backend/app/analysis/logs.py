"""Log normalisation (JSON security events, Linux auth logs) and deterministic log detections."""
import base64
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from ..ingestion.base import EventDraft, parse_ts

BRUTE_FORCE_MIN_FAILURES = 8
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
SPRAY_MIN_USERS = 6


def _get(d: dict, *paths):
    """First non-empty value among dotted paths; supports both nested and flattened ("a.b") keys."""
    for path in paths:
        if path in d and d[path] not in (None, ""):
            return d[path]
        cur = d
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur not in (None, "") and not isinstance(cur, dict):
            return cur
    return None


def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


WIN_EVENTS = {4625: ("authentication", "logon", "failure"), 4624: ("authentication", "logon", "success"), 4648: ("authentication", "explicit_credential_logon", "success"),
              4688: ("process", "process_start", None), 4104: ("process", "powershell_scriptblock", None), 4720: ("authentication", "account_created", "success"),
              4732: ("authentication", "added_to_privileged_group", "success"), 1102: ("file", "audit_log_cleared", None), 7045: ("process", "service_installed", None)}
SYSMON_EVENTS = {1: ("process", "process_start", None), 3: ("network", "connection", None), 22: ("dns", "dns_query", None), 11: ("file", "file_created", None)}


def normalise_json_event(rec: dict, idx: int) -> EventDraft | None:
    if not isinstance(rec, dict):
        return None
    ts = parse_ts(_get(rec, "@timestamp", "timestamp", "TimeCreated", "time", "UtcTime", "event.created", "EventTime", "date", "ts"))
    eid = _int(_get(rec, "EventID", "event_id", "event.code", "winlog.event_id", "eventid"))
    provider = str(_get(rec, "Channel", "winlog.channel", "SourceName", "winlog.provider_name", "provider", "log_name") or "").lower()
    cmd = _get(rec, "CommandLine", "process.command_line", "winlog.event_data.CommandLine", "command_line", "ScriptBlockText", "winlog.event_data.ScriptBlockText", "cmdline")
    image = _get(rec, "Image", "process.executable", "NewProcessName", "winlog.event_data.NewProcessName", "winlog.event_data.Image", "process.name", "exe")
    parent = _get(rec, "ParentImage", "process.parent.executable", "ParentProcessName", "winlog.event_data.ParentProcessName", "winlog.event_data.ParentImage", "process.parent.name")
    user = _get(rec, "TargetUserName", "user.name", "winlog.event_data.TargetUserName", "User", "user", "username", "SubjectUserName", "winlog.event_data.User")
    src = _get(rec, "IpAddress", "source.ip", "winlog.event_data.IpAddress", "src_ip", "SourceIp", "winlog.event_data.SourceIp", "client_ip", "src")
    dst = _get(rec, "destination.ip", "DestinationIp", "winlog.event_data.DestinationIp", "dst_ip", "dest_ip", "dst")
    dport = _int(_get(rec, "destination.port", "DestinationPort", "winlog.event_data.DestinationPort", "dst_port", "dest_port", "dport"))
    host = _get(rec, "host.name", "Computer", "ComputerName", "winlog.computer_name", "hostname", "host")
    domain = _get(rec, "dns.question.name", "QueryName", "winlog.event_data.QueryName", "query", "domain")
    url = _get(rec, "url.full", "url", "request_url")
    category = str(_get(rec, "event.category", "category") or "").lower()
    action = str(_get(rec, "event.action", "action") or "").lower()
    outcome = _get(rec, "event.outcome", "outcome", "result", "status")
    outcome = str(outcome).lower() if outcome is not None else None

    table = SYSMON_EVENTS if "sysmon" in provider else WIN_EVENTS
    if eid in table and (table is SYSMON_EVENTS or eid not in (1, 3, 11, 22)):
        category, action, oc = table[eid]
        outcome = oc or outcome
    elif not category:
        if cmd or image:
            category, action = "process", action or "process_start"
        elif domain and not dst:
            category, action = "dns", action or "dns_query"
        elif dst or dport:
            category, action = "network", action or "connection"
        elif user and (outcome or "login" in action or "logon" in action or "auth" in action):
            category, action = "authentication", action or "logon"
        elif url:
            category, action = "web", action or "request"
        else:
            category, action = "other", action or "event"
    if isinstance(category, list):
        category = str(category[0])
    if outcome in ("failed", "fail", "denied", "error", "false", "0xc000006d"):
        outcome = "failure"
    elif outcome in ("ok", "succeeded", "allowed", "true"):
        outcome = "success"
    if src in ("-", "::1", ""):
        src = None
    data = {k: v for k, v in {"event_id": eid, "command_line": (str(cmd)[:4000] if cmd else None), "image": image, "parent_image": parent,
                              "logon_type": _get(rec, "LogonType", "winlog.event_data.LogonType"), "provider": provider or None}.items() if v is not None}
    summary = f"{category}/{action}" + (f" {outcome}" if outcome else "") + (f" user={user}" if user else "") + (f" src={src}" if src else "") + (f" image={str(image)[-60:]}" if image else "")
    return EventDraft(category=str(category)[:30], action=str(action or "event")[:60], timestamp=ts, outcome=outcome, src_ip=str(src) if src else None,
                      dst_ip=str(dst) if dst else None, dst_port=dport, domain=str(domain).lower() if domain else None, url=str(url) if url else None,
                      user=str(user) if user else None, host=str(host) if host else None, summary=summary[:500], data=data, record_ref=f"record {idx + 1}", key=f"r{idx}")


SYSLOG_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+\-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
SSH_FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?")
SSH_OK = re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
SSH_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
PAM_FAIL = re.compile(r"authentication failure;.*?rhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?")
SUDO = re.compile(r"^\s*(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$")
SUDO_FAIL = re.compile(r"^\s*(?P<user>\S+) : (?:\d+ incorrect password attempts?|user NOT in sudoers)")


def parse_auth_log(text: str, default_year: int) -> tuple[list[EventDraft], int]:
    """Parse sshd/sudo/pam lines. Classic syslog timestamps carry no year; the ingestion year is assumed and recorded in metadata."""
    events, unparsed = [], 0
    for i, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        m = SYSLOG_RE.match(line)
        if not m:
            unparsed += 1
            continue
        raw_ts = m["ts"]
        if raw_ts[0].isdigit():
            ts = parse_ts(raw_ts)
        else:
            try:
                ts = datetime.strptime(f"{default_year} {raw_ts}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                ts = None
        msg, proc, host = m["msg"], m["proc"].lower(), m["host"]
        ev = None
        mk = lambda **kw: EventDraft(timestamp=ts, host=host, record_ref=f"line {i + 1}", key=f"l{i}", data={"process": proc, "raw": line[:400]}, **kw)
        if (x := SSH_FAIL.search(msg)):
            ev = mk(category="authentication", action="ssh_login", outcome="failure", user=x["user"], src_ip=x["ip"], protocol="ssh", summary=f"SSH login failed for {x['user']} from {x['ip']}")
            ev.data["invalid_user"] = "invalid user" in msg
        elif (x := SSH_OK.search(msg)):
            ev = mk(category="authentication", action="ssh_login", outcome="success", user=x["user"], src_ip=x["ip"], protocol="ssh", summary=f"SSH login accepted for {x['user']} from {x['ip']} ({x['method']})")
        elif (x := SSH_INVALID.search(msg)):
            ev = mk(category="authentication", action="ssh_invalid_user", outcome="failure", user=x["user"] or None, src_ip=x["ip"], protocol="ssh", summary=f"SSH invalid user {x['user']} from {x['ip']}")
        elif (x := PAM_FAIL.search(msg)) and "sshd" not in proc:
            ev = mk(category="authentication", action="pam_auth", outcome="failure", user=x["user"], src_ip=x["ip"] if x["ip"] else None, summary=f"PAM authentication failure user={x['user']} rhost={x['ip']}")
        elif proc == "sudo" and (x := SUDO.match(msg)):
            ev = mk(category="process", action="sudo_command", outcome="success", user=x["user"], summary=f"sudo by {x['user']}: {x['cmd'][:120]}")
            ev.data["command_line"] = x["cmd"][:2000]
        elif proc == "sudo" and (x := SUDO_FAIL.match(msg)):
            ev = mk(category="authentication", action="sudo_auth", outcome="failure", user=x["user"], summary=f"sudo authentication failure for {x['user']}")
        if ev:
            events.append(ev)
        else:
            unparsed += 1
    return events, unparsed


PS_PATTERNS = [
    (r"-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{40,}", "encoded_command", 3, "PowerShell launched with a Base64-encoded command"),
    (r"frombase64string", "base64_decode", 2, "decodes Base64 content at runtime"),
    (r"\b(iex|invoke-expression)\b", "invoke_expression", 2, "executes dynamically built code (Invoke-Expression)"),
    (r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|invoke-restmethod", "download_cradle", 3, "downloads remote content"),
    (r"-w(indowstyle)?\s+h(idden)?\b", "hidden_window", 1, "runs with a hidden window"),
    (r"-nop(rofile)?\b", "no_profile", 1, "skips the user profile (-NoProfile)"),
    (r"-e(xecutionpolicy|p)\s+bypass", "execution_policy_bypass", 2, "bypasses the execution policy"),
    (r"amsiutils|amsiinitfailed", "amsi_tamper", 3, "references AMSI internals (anti-malware bypass technique)"),
    (r"add-mppreference\s+-exclusion|set-mppreference\s+-disable", "defender_tamper", 3, "modifies Microsoft Defender settings"),
]
LOLBIN_PATTERNS = [
    (r"certutil(\.exe)?\b.*(-urlcache|-decode)", "certutil", "certutil used to download or decode a file"),
    (r"mshta(\.exe)?\b.*(https?:|javascript:|vbscript:)", "mshta", "mshta executing remote or inline script"),
    (r"regsvr32(\.exe)?\b.*(/i:https?:|scrobj\.dll)", "regsvr32", "regsvr32 scriptlet execution (Squiblydoo pattern)"),
    (r"rundll32(\.exe)?\b.*(javascript:|\\\\temp\\\\|,\s*#\d+)", "rundll32", "rundll32 with script or unusual export"),
    (r"bitsadmin(\.exe)?\b.*/transfer", "bitsadmin", "bitsadmin file transfer"),
    (r"wmic(\.exe)?\b.*process\s+call\s+create", "wmic", "WMIC used to spawn a process"),
    (r"schtasks(\.exe)?\b.*/create", "schtasks", "scheduled task creation"),
    (r"vssadmin(\.exe)?\b.*delete\s+shadows", "vssadmin", "volume shadow copy deletion"),
]


def decode_encoded_command(cmd: str) -> str | None:
    m = re.search(r"-e(?:nc|ncodedcommand|c)?\s+([A-Za-z0-9+/=]{40,})", cmd, re.I)
    if not m:
        return None
    try:
        raw = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))
        txt = raw.decode("utf-16-le", errors="strict")
        return txt[:2000] if sum(c.isprintable() or c.isspace() for c in txt) > 0.9 * max(len(txt), 1) else None
    except (ValueError, UnicodeDecodeError):
        return None


def detect_log_events(events: list[EventDraft]) -> list[dict]:
    out = []
    # --- authentication ---
    auth = [e for e in events if e.category == "authentication" and e.src_ip and e.outcome in ("failure", "success")]
    by_src: dict[str, list[EventDraft]] = defaultdict(list)
    for e in auth:
        by_src[e.src_ip].append(e)
    for src, evs in by_src.items():
        evs.sort(key=lambda e: e.timestamp or datetime.min.replace(tzinfo=timezone.utc))
        fails = [e for e in evs if e.outcome == "failure"]
        if len(fails) < BRUTE_FORCE_MIN_FAILURES:
            continue
        timed = [e for e in fails if e.timestamp]
        best = (0, 0, 0)
        j = 0
        for i in range(len(timed)):
            while timed[i].timestamp - timed[j].timestamp > BRUTE_FORCE_WINDOW:
                j += 1
            if i - j + 1 > best[0]:
                best = (i - j + 1, j, i)
        burst = timed[best[1]:best[2] + 1] if timed and best[0] >= BRUTE_FORCE_MIN_FAILURES else (fails if not timed else [])
        if not burst:
            continue
        users = sorted({e.user for e in burst if e.user})
        spray = len(users) >= SPRAY_MIN_USERS
        span = (burst[-1].timestamp - burst[0].timestamp).total_seconds() if burst[0].timestamp and burst[-1].timestamp else None
        out.append({"detector": "auth.password_spraying" if spray else "auth.brute_force", "severity": "high", "confidence": 0.85, "classification": "suspicious",
                    "title": f"{len(burst)} failed logins from {src}" + (f" across {len(users)} accounts" if spray else f" against {', '.join(users[:3]) or 'unknown user'}"),
                    "description": f"{len(burst)} authentication failures from source {src}" + (f" within {span:.0f} seconds" if span is not None else "") +
                                   f", targeting {len(users)} account(s). Threshold: {BRUTE_FORCE_MIN_FAILURES} failures in {int(BRUTE_FORCE_WINDOW.total_seconds() // 60)} minutes.",
                    "indicators": [src] + users[:10], "event_keys": [e.key for e in burst][:200],
                    "details": {"failures": len(burst), "accounts": users[:30], "window_seconds": span, "source_ip": src}})
        last_fail = burst[-1].timestamp
        succ = [e for e in evs if e.outcome == "success" and e.timestamp and last_fail and timedelta(0) <= e.timestamp - last_fail <= timedelta(minutes=30)]
        if succ:
            s = succ[0]
            out.append({"detector": "auth.success_after_failures", "severity": "critical", "confidence": 0.8, "classification": "suspicious",
                        "title": f"Successful login for {s.user} from {src} after {len(burst)} failures",
                        "description": f"Source {src} authenticated successfully as '{s.user}' at {s.timestamp.isoformat()}, {(s.timestamp - last_fail).total_seconds():.0f}s after a burst of "
                                       f"{len(burst)} failures. This sequence is consistent with a successful password-guessing attack; it is also what a user who finally typed the right password looks like, "
                                       "so the account owner should be asked.",
                        "indicators": [src, s.user], "event_keys": [burst[0].key, burst[-1].key, s.key],
                        "details": {"account": s.user, "source_ip": src, "failures_before": len(burst), "success_at": s.timestamp.isoformat()}})
    # --- process ---
    for e in events:
        cmd = str(e.data.get("command_line") or "")
        if not cmd:
            continue
        low = cmd.lower()
        image = str(e.data.get("image") or "").lower()
        if "powershell" in low or "pwsh" in low or "powershell" in image or e.action == "powershell_scriptblock":
            hits = [(pid, w, d) for (rx, pid, w, d) in PS_PATTERNS if re.search(rx, low)]
            decoded = decode_encoded_command(cmd)
            if decoded:
                hits += [(pid + "_in_decoded", w, d + " (inside the decoded payload)") for (rx, pid, w, d) in PS_PATTERNS[1:] if re.search(rx, decoded.lower())]
            score = sum(w for _, w, _ in hits)
            if score >= 3:
                out.append({"detector": "process.suspicious_powershell", "severity": "high" if score >= 5 else "medium", "confidence": min(0.5 + 0.07 * score, 0.9), "classification": "suspicious",
                            "title": "Suspicious PowerShell execution" + (f" on {e.host}" if e.host else ""),
                            "description": "PowerShell command line " + "; ".join(d for _, _, d in hits) + "." + (" ARGUS decoded the Base64 payload statically (it was not executed)." if decoded else ""),
                            "indicators": [x for x in [e.host, e.user] if x], "event_keys": [e.key],
                            "details": {"command_line": cmd[:1500], "decoded_command": decoded, "matched": [p for p, _, _ in hits], "parent_image": e.data.get("parent_image"), "score": score}})
            office_parent = re.search(r"(winword|excel|powerpnt|outlook)\.exe", str(e.data.get("parent_image") or "").lower())
            if office_parent:
                out.append({"detector": "process.office_spawned_shell", "severity": "high", "confidence": 0.8, "classification": "suspicious",
                            "title": f"{office_parent.group(1)}.exe spawned PowerShell", "description": "An Office application started a PowerShell process, which is the typical execution chain of a malicious document.",
                            "indicators": [x for x in [e.host, e.user] if x], "event_keys": [e.key], "details": {"parent_image": e.data.get("parent_image"), "command_line": cmd[:800]}})
        for rx, name, desc in LOLBIN_PATTERNS:
            if re.search(rx, low):
                out.append({"detector": f"process.lolbin_{name}", "severity": "high" if name == "vssadmin" else "medium", "confidence": 0.65, "classification": "suspicious",
                            "title": f"Living-off-the-land binary use: {desc}", "description": f"Command line matched the pattern for {desc}. These binaries are legitimate system tools; the usage pattern is what is unusual.",
                            "indicators": [x for x in [e.host, e.user] if x], "event_keys": [e.key], "details": {"command_line": cmd[:1500], "binary": name}})
    for e in events:
        if e.action == "audit_log_cleared":
            out.append({"detector": "log.audit_log_cleared", "severity": "high", "confidence": 0.8, "classification": "suspicious", "title": f"Security audit log cleared" + (f" on {e.host}" if e.host else ""),
                        "description": "Event 1102 records that the Security log was cleared, which removes evidence of prior activity.", "indicators": [x for x in [e.host, e.user] if x], "event_keys": [e.key], "details": {}})
    return out
