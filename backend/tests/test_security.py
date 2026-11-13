"""Security tests: SSRF, uploads, traversal, auth, injection, secrets."""
import io

import pytest

from app.security.ssrf import SSRFBlocked, is_public_ip, safe_fetch, validate_destination
from app.security.uploads import UploadRejected, safe_name, sniff_kind, store_original, validate_upload
from conftest import SAMPLES

PUBLIC = lambda host, port: ["93.184.216.34"]


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost/", "http://[::1]/", "http://10.0.0.5/", "http://172.16.3.4/", "http://192.168.1.1/admin", "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/", "http://0.0.0.0/", "http://2130706433/", "http://0x7f.0.0.1/", "http://017700000001/", "http://[::ffff:10.0.0.1]/", "http://100.64.1.1/",
    "http://[fe80::1]/", "http://[fd00:ec2::254]/", "file:///etc/passwd", "gopher://example.com/", "ftp://example.com/x", "http://user:pw@example.com/", "http://example.com:22/",
    "http://example.com:6379/", "http://printer.local/", "http://", "http://[::1", ])
def test_ssrf_blocked_destinations(url):
    with pytest.raises(SSRFBlocked):
        validate_destination(url, PUBLIC)


def test_ssrf_dns_rebinding_style_resolution_blocked():
    with pytest.raises(SSRFBlocked, match="non-public"):
        validate_destination("http://innocent.example.com/", lambda h, p: ["10.1.2.3"])
    with pytest.raises(SSRFBlocked):  # ANY private answer poisons the whole set
        validate_destination("http://mixed.example.com/", lambda h, p: ["93.184.216.34", "127.0.0.1"])
    assert validate_destination("https://ok.example.com/x", PUBLIC) == ("https", "ok.example.com", 443, "93.184.216.34")
    assert is_public_ip("8.8.8.8") and not is_public_ip("::ffff:127.0.0.1") and not is_public_ip("nonsense")


def test_ssrf_redirect_to_internal_is_blocked_before_connecting(monkeypatch):
    """First hop is 'public' and redirects to the metadata service: the second hop must be refused."""
    import http.client
    import socket

    class FakeSock:
        def close(self): pass

    class FakeResp:
        status = 302
        def getheader(self, k): return "http://169.254.169.254/latest/meta-data/" if k == "Location" else None
        def getheaders(self): return []
        def read(self, n): return b""

    connected = []
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: connected.append(addr) or FakeSock())
    monkeypatch.setattr(http.client.HTTPConnection, "request", lambda self, *a, **k: None)
    monkeypatch.setattr(http.client.HTTPConnection, "getresponse", lambda self: FakeResp())
    r = safe_fetch("http://redirector.example.com/", resolver=PUBLIC)
    assert r.blocked and "169.254.169.254" in r.blocked
    assert connected == [("93.184.216.34", 80)]  # connected only to the pinned public address, never to the metadata IP


def test_backend_never_fetches_when_network_disabled(client, new_investigation, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network access attempted")))
    inv = new_investigation()
    assert client.post(f"/api/investigations/{inv}/evidence/url", json={"url": "http://169.254.169.254/latest/meta-data/iam/"}).status_code == 201
    assert client.post(f"/api/investigations/{inv}/start").status_code == 202
    d = client.get(f"/api/investigations/{inv}").json()
    assert d["status"] == "completed"


# ---- uploads ----
def test_filename_sanitisation_and_traversal():
    assert safe_name("../../etc/passwd") == "passwd" and safe_name("..\\..\\windows\\system32\\x.dll") == "x.dll"
    assert safe_name("a\x00b.txt") == "ab.txt" and safe_name("") == "unnamed" and "/" not in safe_name("x/../../y")
    for bad in ("../INV-000000000000", "INV-0000/../..", "inv-abc"):
        with pytest.raises(UploadRejected):
            store_original(bad, "EVD-AAAAAAAAAAAA", b"x")


def test_traversal_filename_upload_is_stored_under_generated_path(client, new_investigation):
    inv = new_investigation()
    r = client.post(f"/api/investigations/{inv}/evidence/file", files={"file": ("../../../../tmp/pwned.eml", (SAMPLES / "benign_email.eml").read_bytes(), "message/rfc822")})
    assert r.status_code == 201 and r.json()["name"] == "pwned.eml"
    from app.config import get_settings
    stored = list(get_settings().storage_dir.rglob("*.bin"))
    assert stored and all(get_settings().storage_dir.resolve() in p.resolve().parents for p in stored)
    assert not __import__("pathlib").Path("/tmp/pwned.eml").exists()


def test_content_sniffing_beats_extension():
    assert sniff_kind(b"MZ\x90\x00" + b"\x00" * 100, "holiday.png") == ("file", "application/x-dosexec")
    assert sniff_kind((SAMPLES / "workstation_capture.pcap").read_bytes()[:4096], "x.txt")[0] == "pcap"
    assert sniff_kind(b"%PDF-1.7 ...", "a.eml")[0] == "pdf" and sniff_kind(b'[{"a":1}]', "x")[0] == "json_events"
    with pytest.raises(UploadRejected, match="does not match"):
        validate_upload(b"MZ\x90\x00binary", "evil.pcap", "pcap")
    with pytest.raises(UploadRejected, match="empty"):
        validate_upload(b"", "x", "auto")
    with pytest.raises(UploadRejected, match="unsupported"):
        validate_upload(b"abc", "x", "../../etc")


def test_malformed_uploads_fail_safely(client, new_investigation):
    inv = new_investigation()
    up = lambda name, data, kind="auto": client.post(f"/api/investigations/{inv}/evidence/file", files={"file": (name, io.BytesIO(data), "application/octet-stream")}, data={"kind": kind})
    assert up("empty.bin", b"").status_code == 422
    assert up("fake.pcap", b"this is not a capture", "pcap").status_code == 422
    assert up("trunc.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 7).status_code == 201     # right magic, truncated header
    assert up("bad.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 40).status_code == 201       # right magic, corrupt body
    assert up("bad.json", b'[{"a": 1}, {"b": ').status_code == 201                      # stored as generic file, not JSON
    assert client.post(f"/api/investigations/{inv}/start").status_code == 202
    d = client.get(f"/api/investigations/{inv}").json()
    assert d["status"] == "completed"                                                   # one bad item must not sink the investigation
    by_name = {e["name"]: e for e in d["evidence"]}
    assert by_name["trunc.pcap"]["status"] == "failed" and by_name["trunc.pcap"]["parse_error"]
    assert by_name["bad.png"]["status"] == "parsed"


def test_oversize_upload_rejected(client, new_investigation, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "max_upload_bytes", 1000)
    inv = new_investigation()
    r = client.post(f"/api/investigations/{inv}/evidence/file", files={"file": ("big.txt", b"A" * 5000, "text/plain")})
    assert r.status_code == 413


def test_invalid_input_rejected(client, new_investigation):
    inv = new_investigation()
    assert client.post("/api/investigations", json={"title": ""}).status_code == 422
    assert client.post("/api/investigations", json={"title": "x" * 500}).status_code == 422
    assert client.post(f"/api/investigations/{inv}/evidence/url", json={"url": "http://a b.com/\n"}).status_code == 422
    assert client.post(f"/api/investigations/{inv}/evidence/text", json={"kind": "pcap", "content": "x"}).status_code == 422
    assert client.post(f"/api/investigations/{inv}/start").status_code == 400            # no evidence yet
    assert client.get("/api/investigations/INV-DOESNOTEXIST").status_code == 404
    assert client.get(f"/api/investigations/{inv}/report").status_code == 404
    assert client.get(f"/api/investigations/{inv}/report/export?format=exe").status_code == 422
    assert client.post("/api/samples/..%2F..%2Fetc").status_code == 404


def test_sql_injection_strings_are_data(client, new_investigation):
    evil = "x'; DROP TABLE investigations; --"
    inv = client.post("/api/investigations", json={"title": evil}).json()["id"]
    assert client.get("/api/investigations", params={"q": "' OR '1'='1"}).json() == []
    assert client.get("/api/search", params={"q": "'; DROP TABLE findings; --"}).status_code == 200
    assert client.get(f"/api/investigations/{inv}").json()["title"] == evil
    assert client.get(f"/api/investigations/{inv}/indicators", params={"q": "%' UNION SELECT * FROM audit_logs --"}).json() == []


def test_authentication_enforced_when_key_configured(client, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "api_key", "correct-horse-battery")
    assert client.get("/api/health").status_code == 200                                  # liveness stays open
    assert client.get("/api/investigations").status_code == 401
    assert client.get("/api/investigations", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/api/investigations", json={"title": "t"}, headers={"X-API-Key": ""}).status_code == 401
    assert client.get("/api/investigations", headers={"X-API-Key": "correct-horse-battery"}).status_code == 200


def test_rate_limit(client, monkeypatch):
    from app import main
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "rate_limit_per_minute", 5)
    main._hits.clear()
    codes = [client.get("/api/health").status_code for _ in range(8)]
    main._hits.clear()
    assert codes[:5] == [200] * 5 and codes[5:] == [429] * 3


def test_secrets_never_leave_the_backend(client, monkeypatch):
    from app.config import get_settings
    s = get_settings()
    for k in ("virustotal_api_key", "abuseipdb_api_key", "otx_api_key", "llm_api_key"):
        monkeypatch.setattr(s, k, "SECRET-" + k)
    body = client.get("/api/system").text + client.get("/api/audit").text + client.get("/api/openapi.json").text
    assert "SECRET-" not in body
    assert client.get("/api/system").json()["threat_intel"]["providers"][1]["reason"].startswith("offline mode")


def test_production_requires_api_key(monkeypatch):
    from app.config import Settings, get_settings
    monkeypatch.setenv("ARGUS_ENV", "production")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="ARGUS_API_KEY"):
            get_settings()
    finally:
        monkeypatch.setenv("ARGUS_ENV", "local")
        get_settings.cache_clear()
        get_settings()


def test_html_report_escapes_evidence_content(client, new_investigation):
    inv = client.post("/api/investigations", json={"title": "<script>alert(1)</script>"}).json()["id"]
    client.post(f"/api/investigations/{inv}/evidence/url", json={"url": "http://paypa1.example/login?x=<img/src=x/onerror=alert(1)>"})
    client.post(f"/api/investigations/{inv}/start")
    html = client.get(f"/api/investigations/{inv}/report/export?format=html").text
    assert "<script>alert(1)</script>" not in html and "<img/src=x" not in html and "&lt;script&gt;" in html
