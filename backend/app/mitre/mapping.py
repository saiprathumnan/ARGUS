"""MITRE ATT&CK mapping. Techniques are a curated subset of Enterprise ATT&CK (ids, names and tactics as
published at https://attack.mitre.org, checked against ATT&CK v16). A mapping is created only for a
verified finding whose detector has an explicit rule below; the rationale cites what the evidence showed."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Finding, MitreMapping

ATTACK_VERSION = "Enterprise ATT&CK v16 (curated subset)"
T = {
    "T1566.001": ("Phishing: Spearphishing Attachment", ["initial-access"]),
    "T1566.002": ("Phishing: Spearphishing Link", ["initial-access"]),
    "T1656": ("Impersonation", ["defense-evasion"]),
    "T1036.007": ("Masquerading: Double File Extension", ["defense-evasion"]),
    "T1583.001": ("Acquire Infrastructure: Domains", ["resource-development"]),
    "T1110.001": ("Brute Force: Password Guessing", ["credential-access"]),
    "T1110.003": ("Brute Force: Password Spraying", ["credential-access"]),
    "T1078": ("Valid Accounts", ["defense-evasion", "persistence", "privilege-escalation", "initial-access"]),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ["execution"]),
    "T1027.010": ("Obfuscated Files or Information: Command Obfuscation", ["defense-evasion"]),
    "T1105": ("Ingress Tool Transfer", ["command-and-control"]),
    "T1204.002": ("User Execution: Malicious File", ["execution"]),
    "T1218.005": ("System Binary Proxy Execution: Mshta", ["defense-evasion"]),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", ["defense-evasion"]),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", ["defense-evasion"]),
    "T1197": ("BITS Jobs", ["defense-evasion", "persistence"]),
    "T1047": ("Windows Management Instrumentation", ["execution"]),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", ["execution", "persistence", "privilege-escalation"]),
    "T1490": ("Inhibit System Recovery", ["impact"]),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ["defense-evasion"]),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ["defense-evasion"]),
    "T1071.001": ("Application Layer Protocol: Web Protocols", ["command-and-control"]),
    "T1071.004": ("Application Layer Protocol: DNS", ["command-and-control"]),
    "T1571": ("Non-Standard Port", ["command-and-control"]),
    "T1029": ("Scheduled Transfer", ["exfiltration"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["exfiltration"]),
    "T1041": ("Exfiltration Over C2 Channel", ["exfiltration"]),
    "T1046": ("Network Service Discovery", ["discovery"]),
    "T1505.003": ("Server Software Component: Web Shell", ["persistence"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["defense-evasion"]),
}


def url_for(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def _rules(f: Finding) -> list[tuple[str, str, float]]:
    """Return [(technique_id, rationale, confidence)] for one finding."""
    d, det, out = f.details or {}, f.detector, []
    sig_ids = {s["id"] for s in d.get("signals", [])}
    if det == "email.link_text_mismatch":
        out.append(("T1566.002", "The email contains a link whose visible text names one domain while the destination is another, the defining trait of a deceptive phishing link.", 0.8))
    elif det in ("email.attachment_double_extension", "email.attachment_executable", "email.attachment_macro_document"):
        out.append(("T1566.001", f"The email delivers an attachment of a code-capable type ({d.get('filename', 'attachment')}).", 0.7))
        if det == "email.attachment_double_extension":
            out.append(("T1036.007", "The attachment name uses a double extension to hide its executable type.", 0.8))
    elif det in ("email.display_name_spoof", "email.brand_display_name"):
        out.append(("T1656", "The sender's display name presents an identity that the sending address does not belong to.", 0.6))
    elif det == "url.structure" and f.classification == "suspicious" and sig_ids & {"typosquat", "homoglyph", "brand_in_hostname", "brand_on_unofficial_tld"}:
        out.append(("T1583.001", "The hostname imitates a known brand (look-alike domain), which indicates a domain registered for deception.", 0.55))
    elif det == "correlation.delivery_to_contact" and d.get("sequence") == "contact_after_delivery" and str(d.get("chain", [{}])[0].get("from", "")).startswith("url:"):
        out.append(("T1566.002", "A URL delivered in collected content was followed by network contact with its hosting infrastructure from an internal host (ordering inferred from timestamps).", 0.6))
    elif det == "auth.brute_force":
        out.append(("T1110.001", f"{d.get('failures')} failed authentications from one source against {len(d.get('accounts', []))} account(s) inside the detection window.", 0.85))
    elif det == "auth.password_spraying":
        out.append(("T1110.003", f"One source failed authentication against {len(d.get('accounts', []))} different accounts in a short window.", 0.8))
    elif det == "auth.success_after_failures":
        out.append(("T1078", f"Account '{d.get('account')}' authenticated successfully from the same source immediately after {d.get('failures_before')} failures, consistent with a guessed credential being used.", 0.6))
    elif det == "process.suspicious_powershell":
        m = set(d.get("matched", []))
        out.append(("T1059.001", "A PowerShell command line with attack-associated options was executed.", 0.85))
        if "encoded_command" in m:
            out.append(("T1027.010", "The command was passed Base64-encoded (-EncodedCommand), hiding its content from casual inspection.", 0.8))
        if m & {"download_cradle", "download_cradle_in_decoded"}:
            out.append(("T1105", "The command (or its decoded payload) downloads content from a remote location.", 0.75))
        if m & {"defender_tamper", "amsi_tamper", "defender_tamper_in_decoded", "amsi_tamper_in_decoded"}:
            out.append(("T1562.001", "The command modifies or bypasses endpoint protection.", 0.75))
    elif det == "process.office_spawned_shell":
        out.append(("T1204.002", "An Office application spawned PowerShell, the execution chain of a malicious document opened by a user.", 0.7))
    elif det.startswith("process.lolbin_"):
        tid = {"certutil": "T1105", "mshta": "T1218.005", "regsvr32": "T1218.010", "rundll32": "T1218.011", "bitsadmin": "T1197", "wmic": "T1047", "schtasks": "T1053.005", "vssadmin": "T1490"}.get(d.get("binary"))
        if tid:
            out.append((tid, f"Command line shows {d.get('binary')} used in the pattern associated with this technique.", 0.7))
    elif det == "log.audit_log_cleared":
        out.append(("T1070.001", "Event 1102 records the Security event log being cleared.", 0.85))
    elif det == "network.beaconing":
        out.append(("T1071.001" if d.get("port") in (80, 443, 8080, 8443) else "T1571", f"Connections repeat every ~{d.get('interval_mean_s')}s with very low jitter (CV {d.get('interval_cv')}) to port {d.get('port')}, "
                    "the timing signature of automated check-ins. The application protocol was not decoded.", 0.5))
    elif det == "network.suspicious_port":
        out.append(("T1571", f"Traffic used port {d.get('port')}, which is not a standard service port for the observed peers.", 0.45))
    elif det == "network.dns_tunneling_pattern":
        out.append(("T1071.004", f"{d.get('unique_subdomains')} unique long high-entropy subdomains were queried under one parent domain, the pattern produced by DNS-based C2 or tunnelling.", 0.6))
    elif det == "network.large_outbound_transfer":
        out.append(("T1048", "A large upload-dominant flow to an external host was captured. The channel and content were not identified.", 0.4))
    elif det == "network.port_scan":
        out.append(("T1046", f"One host contacted {d.get('distinct_ports')} distinct ports on a single target.", 0.75))
    elif det == "file.yara_match" and d.get("rule_class") != "test_fixture":
        tid = {"ARGUS_PowerShell_Encoded_Downloader": "T1059.001", "ARGUS_Office_Macro_AutoExec_Shell": "T1204.002", "ARGUS_Webshell_Eval_Request": "T1505.003"}.get(d.get("rule"))
        if tid:
            out.append((tid, f"File content matched YARA rule {d.get('rule')}, which encodes this technique's static pattern.", 0.65))
    elif det == "file.double_extension":
        out.append(("T1036.007", "The file name carries a document extension followed by an executable extension.", 0.8))
    return out


def map_findings(db: Session, inv: str) -> int:
    n = 0
    for f in db.scalars(select(Finding).where(Finding.investigation_id == inv)):
        if f.verification_status not in ("verified", "downgraded") or f.classification not in ("suspicious", "confirmed_malicious"):
            continue
        for tid, rationale, conf in _rules(f):
            name, tactics = T[tid]
            db.add(MitreMapping(investigation_id=inv, finding_id=f.id, technique_id=tid, technique_name=name, tactics=tactics, rationale=rationale, reference_url=url_for(tid),
                                confidence=round(conf * min(1.0, f.confidence + 0.2), 3)))
            n += 1
    db.flush()
    return n
