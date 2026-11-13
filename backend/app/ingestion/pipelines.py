"""Ingestion pipelines. One function per evidence kind, registered with @pipeline(kind).
Each pipeline: parse -> normalise into the common schema -> run the deterministic detectors for that kind."""
import json
import tempfile
import os
from collections import defaultdict
from datetime import datetime, timezone

from ..analysis import email as email_an
from ..analysis import file as file_an
from ..analysis import logs as logs_an
from ..analysis import network as net_an
from ..analysis.ioc import extract_iocs, is_ip, is_private_ip, registered_domain
from ..analysis.url import analyse_url, classify_score
from ..config import get_settings
from ..ml import anomaly as anomaly_ml
from ..ml import phishing as phishing_ml
from ..security.ssrf import safe_fetch
from ..vision import similarity
from .base import EventDraft, FindingDraft, IngestContext, ParsedEvidence, RelationDraft, pipeline, to_utc

MAX_EVENTS = 20_000


def process_url(pe: ParsedEvidence, raw_url: str, context: str, ts: datetime | None = None, live: bool = True) -> dict:
    """Shared URL handling: indicators, structural finding, ML prediction, optional guarded live fetch."""
    a = analyse_url(raw_url)
    url = a["url"]
    pe.add_ioc("url", url, context, ts)
    if not a.get("valid"):
        pe.findings.append(FindingDraft("url.malformed", f"Malformed URL: {raw_url[:120]}", "low", "insufficient_evidence", "deterministic", 0.4,
                                        a["signals"][0]["detail"], [url], details={"signals": a["signals"]}))
        return a
    host = a["host"]
    if is_ip(host):
        pe.add_ioc("ip", host, f"host of {context}", ts)
        pe.relations.append(RelationDraft(("url", url), ("ip", host), "hosted_on", "derived", 1.0, "The URL's host component is this IP address."))
    else:
        pe.add_ioc("domain", host, f"host of {context}", ts)
        pe.relations.append(RelationDraft(("url", url), ("domain", host), "hosted_on", "derived", 1.0, "The URL's host component is this domain."))
    cls, sev, conf = classify_score(a["score"])
    if a["signals"]:
        pe.findings.append(FindingDraft("url.structure", f"{len(a['signals'])} structural indicator(s) in URL {url[:90]}", sev, cls, "deterministic", conf,
                                        "; ".join(s["detail"] for s in a["signals"]) + ". Structural analysis only: the page content was not inspected.",
                                        [url, host], details={"signals": a["signals"], "score": a["score"], "registered_domain": a["registered_domain"]}))
    else:
        pe.findings.append(FindingDraft("url.structure", f"No suspicious structural indicators in URL {url[:90]}", "info", "benign", "deterministic", 0.5,
                                        "None of the URL heuristics fired. Absence of structural indicators does not establish that the destination is safe.",
                                        [url, host], details={"signals": [], "score": 0, "registered_domain": a["registered_domain"]}))
    pred = phishing_ml.predict(url)
    if pred is not None:
        a["ml"] = pred
        if pred["probability"] >= pred["threshold"]:
            pe.findings.append(FindingDraft("ml.phishing_url", f"Phishing classifier score {pred['probability']:.2f} for {url[:90]}", "medium", "suspicious", "ml_model", round(pred["probability"] * 0.8, 3),
                                            f"The lexical URL classifier (Random Forest) assigned phishing probability {pred['probability']:.2f} (finding threshold {pred['threshold']}). "
                                            "This is a statistical prediction from the URL string alone, not verified intelligence.",
                                            [url], details=pred))
    s = get_settings()
    if live and s.allow_network_fetch:
        r = safe_fetch(url, timeout=s.fetch_timeout_seconds, max_redirects=s.fetch_max_redirects, max_bytes=s.fetch_max_bytes)
        fetch = {"fetched_at": r.fetched_at, "blocked": r.blocked, "error": r.error, "status": r.status, "final_url": r.final_url,
                 "hops": [h.__dict__ for h in r.hops], "tls": r.tls, "content_type": r.headers.get("content-type"), "body_bytes": len(r.body)}
        a["fetch"] = fetch
        if r.blocked:
            pe.findings.append(FindingDraft("url.fetch_blocked", f"Live fetch refused by SSRF policy: {r.blocked}", "medium", "suspicious", "deterministic", 0.7,
                                            "The URL (or one of its redirects) points at an internal, loopback, link-local or metadata address. ARGUS did not connect.", [url], details=fetch))
        elif len(r.hops) > 1:
            domains = [registered_domain(h.url.split("/")[2].split(":")[0]) for h in r.hops if h.url.count("/") >= 2]
            cross = len(set(d for d in domains if d)) > 1
            pe.findings.append(FindingDraft("url.redirect_chain", f"{len(r.hops) - 1} redirect(s) ending at {r.final_url[:90]}", "low" if not cross else "medium",
                                            "insufficient_evidence" if not cross else "suspicious", "deterministic", 0.5,
                                            f"Observed redirect chain at {r.fetched_at}: " + " -> ".join(h.url[:80] for h in r.hops) + ".", [url, r.final_url], details=fetch))
            for h in r.hops:
                if h.ip:
                    hh = h.url.split("/")[2].split(":")[0]
                    pe.add_ioc("ip", h.ip, f"address ARGUS connected to for {hh} at {r.fetched_at}")
                    if not is_ip(hh):
                        pe.relations.append(RelationDraft(("domain", hh), ("ip", h.ip), "resolves_to", "observed", 0.9, f"Live DNS resolution by ARGUS at {r.fetched_at}."))
    return a


@pipeline("url")
def ingest_url(data: bytes, ctx: IngestContext) -> ParsedEvidence:
    pe = ParsedEvidence()
    raw = data.decode("utf-8", errors="replace").strip()
    a = process_url(pe, raw, "submitted URL")  # no first_seen: submission time is not an observation time
    pe.meta = {"submitted": raw, "normalised": a["url"], "host": a.get("host"), "registered_domain": a.get("registered_domain"),
               "live_fetch": a.get("fetch", "disabled (ARGUS_ALLOW_NETWORK_FETCH=false)"), "ml": a.get("ml")}
    pe.events.append(EventDraft("web", "url_submitted", ctx.ingested_at, url=a["url"], domain=a.get("host") or None, summary=f"URL submitted for analysis: {a['url'][:200]}", record_ref="submission", key="u0"))
    return pe


def _ingest_email(data: bytes, ctx: IngestContext, headers_only: bool) -> ParsedEvidence:
    pe = ParsedEvidence()
    p = email_an.parse_email(data)
    ts = to_utc(p["date"])
    pe.meta = {"from": p["from_addr"], "from_name": p["from_name"], "reply_to": p["reply_to"], "return_path": p["return_path"], "to": p["to"], "subject": p["subject"][:300],
               "date": ts.isoformat() if ts else None, "message_id": p["message_id"][:300], "authentication": p["auth"], "received_hops": len(p["received"]),
               "received_ips": p["received_ips"], "x_mailer": p["x_mailer"][:120], "link_count": len(p["links"]), "attachments": p["attachments"], "headers_only": headers_only}
    for addr, c in ((p["from_addr"], "From header"), (p["reply_to"], "Reply-To header"), (p["return_path"], "Return-Path header")):
        if addr:
            pe.add_ioc("email", addr, c, ts)
            dom = addr.rsplit("@", 1)[-1]
            pe.add_ioc("domain", dom, f"domain of {c}", ts)
            pe.relations.append(RelationDraft(("email", addr), ("domain", dom), "uses_domain", "derived", 1.0, "Domain part of the email address."))
    for ip in p["received_ips"]:
        if not is_private_ip(ip):
            pe.add_ioc("ip", ip, "Received header (mail relay)", ts)
    if p["from_addr"] and p["received_ips"]:
        origin = next((ip for ip in reversed(p["received_ips"]) if not is_private_ip(ip)), None)
        if origin:
            pe.relations.append(RelationDraft(("email", p["from_addr"]), ("ip", origin), "sent_via", "observed", 0.7,
                                              "Earliest public relay recorded in the Received chain. Received headers below the first trusted hop can be forged."))
    pe.events.append(EventDraft("email", "email_received", ts, user=p["to"][0] if p["to"] else None, summary=f"Email '{p['subject'][:120]}' from {p['from_addr']}",
                                data={"subject": p["subject"][:300], "from": p["from_addr"], "auth": p["auth"]}, record_ref="headers", key="m0"))
    dets, _ = email_an.detect_email(p)
    for d in dets:
        pe.findings.append(FindingDraft(d["detector"], d["title"], d["severity"], d["classification"], "deterministic", d["confidence"], d["description"], d["indicators"], ["m0"], d["details"]))
    for a in p["attachments"]:
        pe.add_ioc("sha256", a["sha256"], f"attachment {a['filename']}", ts)
    link_results = []
    for l in p["links"][:40]:
        if l["href"].lower().startswith(("http://", "https://", "hxxp")):
            a = process_url(pe, l["href"], "link in email body", ts)
            link_results.append({"url": a["url"], "score": a.get("score"), "ml_probability": (a.get("ml") or {}).get("probability")})
            if p["from_addr"]:
                pe.relations.append(RelationDraft(("email", p["from_addr"]), ("url", a["url"]), "links_to", "observed", 1.0, "URL present in the body of the message sent from this address.", ["m0"]))
    pe.meta["links"] = link_results
    return pe


@pipeline("eml")
def ingest_eml(data: bytes, ctx: IngestContext) -> ParsedEvidence:
    return _ingest_email(data, ctx, headers_only=False)


@pipeline("email_headers")
def ingest_headers(data: bytes, ctx: IngestContext) -> ParsedEvidence:
    return _ingest_email(data.rstrip() + b"\r\n\r\n", ctx, headers_only=True)


def _finish_log(pe: ParsedEvidence, events: list[EventDraft]):
    """Shared tail for log pipelines: indicators, relations and detections from normalised events."""
    pe.events = events[:MAX_EVENTS]
    seen = set()
    auth_pairs: dict[tuple, list] = defaultdict(list)
    for e in pe.events:
        for t, v, c in (("ip", e.src_ip, "source address"), ("ip", e.dst_ip, "destination address"), ("user", e.user, "account"), ("host", e.host, "host"), ("domain", e.domain, "queried / contacted domain"), ("url", e.url, "requested URL")):
            if v and (t, v) not in seen:
                seen.add((t, v))
                pe.add_ioc(t, v, f"{c} in {e.record_ref}", e.timestamp)
        if e.category == "authentication" and e.src_ip and e.user:
            auth_pairs[(e.src_ip, e.user, e.outcome)].append(e)
        if e.category == "network" and e.src_ip and e.dst_ip:
            auth_pairs[("net", e.src_ip, e.dst_ip)].append(e)
        cmd = str(e.data.get("command_line") or "")
        decoded = logs_an.decode_encoded_command(cmd) if cmd else None
        for kind, vals in extract_iocs(cmd + " " + (decoded or "")).items():
            for v in vals[:10]:
                if kind in ("url", "ip", "domain") and (kind, v) not in seen and not (kind == "domain" and v.endswith((".exe", ".dll", ".ps1"))):
                    seen.add((kind, v))
                    if kind == "url":
                        a = analyse_url(v)
                        pe.add_ioc("url", a["url"], f"URL in command line ({e.record_ref})", e.timestamp)
                        if a.get("host"):
                            pe.add_ioc("ip" if is_ip(a["host"]) else "domain", a["host"], f"host of URL in command line ({e.record_ref})", e.timestamp)
                            pe.relations.append(RelationDraft(("url", a["url"]), ("ip" if is_ip(a["host"]) else "domain", a["host"]), "hosted_on", "derived", 1.0, "The URL's host component."))
                        if e.host:
                            pe.relations.append(RelationDraft(("host", e.host), ("url", a["url"]), "referenced_url", "observed", 0.9, f"URL appears in a process command line on this host ({e.record_ref}).", [e.key], e.timestamp, e.timestamp))
                    else:
                        pe.add_ioc(kind, v, f"in command line ({e.record_ref})", e.timestamp)
    for k, evs in auth_pairs.items():
        ts = sorted(e.timestamp for e in evs if e.timestamp)
        first, last = (ts[0], ts[-1]) if ts else (None, None)
        if k[0] == "net":
            pe.relations.append(RelationDraft(("ip", k[1]), ("ip", k[2]), "connects_to", "observed", 0.95, f"{len(evs)} network event(s) logged between these addresses.", [e.key for e in evs][:50], first, last, len(evs)))
        else:
            rel = "authenticated_as" if k[2] == "success" else "failed_login_as"
            pe.relations.append(RelationDraft(("ip", k[0]), ("user", k[1]), rel, "observed", 0.95, f"{len(evs)} {k[2] or 'unknown-outcome'} authentication event(s) from this address for this account.", [e.key for e in evs][:50], first, last, len(evs)))
    for d in logs_an.detect_log_events(pe.events):
        pe.findings.append(FindingDraft(d["detector"], d["title"], d["severity"], d["classification"], "deterministic", d["confidence"], d["description"], d["indicators"], d["event_keys"], d["details"]))


@pipeline("json_events")
def ingest_json(data: bytes, ctx: IngestContext) -> ParsedEvidence:
    pe = ParsedEvidence()
    text = data.decode("utf-8", errors="replace")
    records, bad = [], 0
    try:
        doc = json.loads(text)
        if isinstance(doc, dict):
            doc = next((doc[k] for k in ("events", "records", "Records", "hits", "logs", "data") if isinstance(doc.get(k), list)), [doc])
        records = doc if isinstance(doc, list) else []
    except ValueError:
        for line in text.splitlines():
            if line.strip():
                try:
                    records.append(json.loads(line))
                except ValueError:
                    bad += 1
    records = [(r.get("_source", r) if isinstance(r, dict) else r) for r in records]
    events = [e for e in (logs_an.normalise_json_event(r, i) for i, r in enumerate(records[:MAX_EVENTS])) if e is not None]
    ts = sorted(e.timestamp for e in events if e.timestamp)
    cats = defaultdict(int)
    for e in events:
        cats[e.category] += 1
    pe.meta = {"records": len(records), "normalised_events": len(events), "unparseable_lines": bad, "truncated": len(records) > MAX_EVENTS, "categories": dict(cats),
               "first_event": ts[0].isoformat() if ts else None, "last_event": ts[-1].isoformat() if ts else None, "events_without_timestamp": len(events) - len(ts)}
    _finish_log(pe, events)
    return pe


@pipeline("auth_log")
def ingest_auth(data: bytes, ctx: IngestContext) -> ParsedEvidence:
    pe = ParsedEvidence()
    events, unparsed = logs_an.parse_auth_log(data.decode("utf-8", errors="replace"), ctx.ingested_at.year)
    ts = sorted(e.timestamp for e in events if e.timestamp)
    pe.meta = {"lines": data.count(b"\n") + 1, "normalised_events": len(events), "lines_not_recognised": unparsed, "assumed_year": ctx.ingested_at.year,
               "year_note": "Classic syslog timestamps carry no year; the ingestion year was assumed.", "first_event": ts[0].isoformat() if ts else None, "last_event": ts[-1].isoformat() if ts else None}
    _finish_log(pe, events)
    return pe


@pipeline("pcap")
def ingest_pcap(data: bytes, ctx: IngestContext) -> ParsedEvidence:
    pe = ParsedEvidence()
    fd, tmp = tempfile.mkstemp(prefix="argus-", suffix=".pcap")  # 0600, removed in finally
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        parsed = net_an.parse_pcap(tmp)
    finally:
        os.unlink(tmp)
    flows = parsed["flows"]
    fan = defaultdict(set)
    for f in flows.values():
        fan[(f.client, f.server)].add(f.port)
    pe.meta = {"packets": parsed["packet_count"], "truncated": parsed["truncated"], "flows": len(flows), "dns_queries": len(parsed["dns"]), "protocols": parsed["protocols"],
               "capture_start": net_an.ts_dt(parsed["first_ts"]).isoformat() if parsed["first_ts"] else None, "capture_end": net_an.ts_dt(parsed["last_ts"]).isoformat() if parsed["last_ts"] else None}
    seen = set()

    def ioc(t, v, c, ts):
        if (t, v) not in seen:
            seen.add((t, v))
            pe.add_ioc(t, v, c, ts)

    ordered = sorted(flows.values(), key=lambda f: -(len(f.sizes_out) + len(f.sizes_in)))[:3000]
    feats = []
    for f in ordered:
        t0, t1 = net_an.ts_dt(f.first), net_an.ts_dt(f.last)
        ioc("ip", f.client, "flow initiator", t0)
        ioc("ip", f.server, "flow responder", t0)
        ft = net_an.flow_features(f, len(fan[(f.client, f.server)]))
        feats.append(ft)
        pe.events.append(EventDraft("network", "flow", t0, src_ip=f.client, dst_ip=f.server, dst_port=f.port, protocol=f.proto, domain=f.sni or f.http_host,
                                    summary=f"{f.client} -> {f.server}:{f.port}/{f.proto} {len(f.starts)} conn, {sum(f.sizes_out)}B out / {sum(f.sizes_in)}B in",
                                    data={"connections": len(f.starts), "bytes_out": sum(f.sizes_out), "bytes_in": sum(f.sizes_in), "packets": len(f.sizes_out) + len(f.sizes_in),
                                          "last_seen": t1.isoformat() if t1 else None, "sni": f.sni, "http_host": f.http_host, "http_requests": f.http_paths},
                                    record_ref=f"flow {f.key()} (first packet #{f.first_packet_no})", key=f.key()))
        pe.relations.append(RelationDraft(("ip", f.client), ("ip", f.server), "connects_to", "observed", 1.0,
                                          f"{len(f.starts)} connection(s) to port {f.port}/{f.proto} captured, {len(f.sizes_out) + len(f.sizes_in)} packets.", [f.key()], t0, t1, max(len(f.starts), 1)))
        name = f.sni or (f.http_host.split(":")[0] if f.http_host else None)
        if name and not is_ip(name):
            ioc("domain", name, "TLS SNI" if f.sni else "HTTP Host header", t0)
            pe.relations.append(RelationDraft(("domain", name), ("ip", f.server), "served_by", "observed", 0.9,
                                              f"Client named this host ({'TLS SNI' if f.sni else 'HTTP Host header'}) in a connection to this address.", [f.key()], t0, t1))
        for req in f.http_paths[:5]:
            parts = req.split(" ", 1)
            if f.http_host and len(parts) == 2:
                u = f"http://{f.http_host}{parts[1]}"
                ioc("url", u, "HTTP request line in capture", t0)
                pe.relations.append(RelationDraft(("url", u), ("domain" if not is_ip(f.http_host.split(':')[0]) else "ip", f.http_host.split(":")[0]), "hosted_on", "derived", 1.0, "The URL's host component.", [f.key()]))
    for q in parsed["dns"][:5000]:
        t0 = net_an.ts_dt(q["first"])
        k = f"dns:{q['client']}:{q['qname']}"
        ioc("domain", q["qname"], "DNS query name", t0)
        pe.events.append(EventDraft("dns", "dns_query", t0, src_ip=q["client"], dst_ip=q["resolver"], dst_port=53, protocol="dns", domain=q["qname"],
                                    summary=f"{q['client']} queried {q['qname']}" + (f" -> {', '.join(q['answers'][:3])}" if q["answers"] else ""),
                                    data={"count": q["count"], "answers": q["answers"]}, record_ref=f"DNS (first packet #{q['packet_no']})", key=k))
        pe.relations.append(RelationDraft(("ip", q["client"]), ("domain", q["qname"]), "queried", "observed", 1.0, f"{max(q['count'], 1)} DNS query(ies) captured.", [k], t0, net_an.ts_dt(q["last"]), max(q["count"], 1)))
        for ans in q["answers"]:
            ioc("ip", ans, f"DNS answer for {q['qname']}", t0)
            pe.relations.append(RelationDraft(("domain", q["qname"]), ("ip", ans), "resolves_to", "observed", 1.0, "A/AAAA record in a DNS response present in the capture.", [k], t0, t0))
    for d in net_an.detect_network(parsed):
        keys = d.get("flows") or [f"dns:{d['indicators'][0]}:{q}" for q in d.get("qnames", [])]
        pe.findings.append(FindingDraft(d["detector"], d["title"], d["severity"], "suspicious", "deterministic", d["confidence"], d["description"], d["indicators"], keys, d["details"]))
    scores = anomaly_ml.score_flows(feats)
    if scores is None:
        pe.meta["anomaly_model"] = "not installed (run python -m app.ml.train_anomaly)"
    else:
        flagged = [(f, s) for f, s in zip(ordered, scores) if s["anomalous"]]
        pe.meta["anomaly_model"] = {"flows_scored": len(scores), "flows_flagged": len(flagged)}
        for f, s in sorted(flagged, key=lambda x: -x[1]["score"])[:15]:
            dev = "; ".join(f"{d['feature']}={d['value']} (baseline median {d['baseline_median']})" for d in s["deviations"]) or "no single feature outside the baseline range; the combination is unusual"
            pe.findings.append(FindingDraft("ml.network_anomaly", f"Anomalous flow {f.client} -> {f.server}:{f.port}/{f.proto} (score {s['score']:.3f})", "low", "suspicious", "ml_model", 0.4,
                                            f"Isolation Forest flagged this flow as statistically unusual relative to its training baseline. Notable deviations: {dev}. "
                                            "The baseline is synthetic; an anomaly is rarity, not evidence of malice.", [f.client, f.server], [f.key()], s))
    return pe


def _ingest_file(data: bytes, ctx: IngestContext, mime: str) -> ParsedEvidence:
    pe = ParsedEvidence()
    a = file_an.analyse_file(data, ctx.filename, mime)
    pe.meta = {k: a[k] for k in ("sha256", "sha1", "md5", "size", "mime", "entropy", "string_count", "suspicious_strings", "pe", "double_extension")}
    pe.meta["yara_matches"] = [m["rule"] for m in a["yara"]]
    if "pdf" in a:
        pe.meta["pdf"] = a["pdf"]
    pe.meta["executed"] = False
    pe.add_ioc("sha256", a["sha256"], f"hash of {ctx.filename}")
    pe.events.append(EventDraft("file", "file_submitted", ctx.ingested_at, summary=f"File {ctx.filename} ({a['size']} bytes, {mime}) submitted", data={"sha256": a["sha256"]}, record_ref="file", key="f0"))
    for kind in ("url", "ip", "domain"):
        for v in a["iocs"][kind][:40]:
            if kind == "ip" and is_private_ip(v):
                continue
            if kind == "url":
                u = process_url(pe, v, "string embedded in file", live=False)
                pe.relations.append(RelationDraft(("sha256", a["sha256"]), ("url", u["url"]), "embeds", "observed", 1.0, "URL string found in the file's contents."))
            else:
                pe.add_ioc(kind, v, "string embedded in file")
                pe.relations.append(RelationDraft(("sha256", a["sha256"]), (kind, v), "embeds", "observed", 0.8, f"{kind} string found in the file's contents."))
    for d in file_an.detect_file(a, ctx.filename):
        pe.findings.append(FindingDraft(d["detector"], d["title"], d["severity"], d["classification"], d["basis"], d["confidence"], d["description"], d["indicators"], ["f0"], d["details"]))
    if not pe.findings:
        pe.findings.append(FindingDraft("file.static_clean", f"No static indicators in {ctx.filename}", "info", "benign", "deterministic", 0.4,
                                        "No bundled YARA rule matched and no suspicious strings were found. Static analysis cannot rule out malicious behaviour.", [a["sha256"]], ["f0"]))
    return pe


@pipeline("file")
def ingest_file(data: bytes, ctx: IngestContext) -> ParsedEvidence:
    return _ingest_file(data, ctx, ctx.meta.get("mime", "application/octet-stream"))


@pipeline("pdf")
def ingest_pdf(data: bytes, ctx: IngestContext) -> ParsedEvidence:
    return _ingest_file(data, ctx, "application/pdf")


@pipeline("screenshot")
def ingest_screenshot(data: bytes, ctx: IngestContext) -> ParsedEvidence:
    pe = ParsedEvidence()
    cmp_ = similarity.compare(data)
    pe.meta = {"image": similarity.metadata(data), "similarity": cmp_, "source_url": ctx.meta.get("source_url"),
               "source_url_note": "Analyst-asserted capture URL; ARGUS did not capture this screenshot itself." if ctx.meta.get("source_url") else None}
    pe.events.append(EventDraft("web", "screenshot_submitted", ctx.ingested_at, url=ctx.meta.get("source_url"), summary=f"Screenshot {ctx.filename} submitted", record_ref="image", key="s0"))
    if ctx.meta.get("source_url"):
        a = process_url(pe, ctx.meta["source_url"], "analyst-asserted source of screenshot", live=False)
        pe.meta["source_registered_domain"] = a.get("registered_domain")
    if "error" in cmp_:
        pe.findings.append(FindingDraft("vision.undecodable", "Screenshot could not be decoded", "info", "insufficient_evidence", "visual_similarity", 0.9, cmp_["error"], [], ["s0"]))
        return pe
    best = cmp_["matches"][0] if cmp_["matches"] else None
    if best and best["is_match"]:
        pe.findings.append(FindingDraft("vision.reference_similarity", f"Screenshot resembles reference page '{best['reference']}' (similarity {best['combined']:.2f})", "low", "insufficient_evidence", "visual_similarity",
                                        round(best["combined"] * 0.7, 3),
                                        f"Combined similarity {best['combined']:.2f} (pHash {best['phash_similarity']}, dHash {best['dhash_similarity']}, colour {best['colour_similarity']}, ORB {best['orb_similarity']} "
                                        f"with {best['orb_good_matches']} keypoint matches). Visual similarity alone does not establish impersonation: a screenshot of the genuine page scores the same.",
                                        [], ["s0"], {"best_match": best, "all_matches": cmp_["matches"]}))
    elif cmp_["reference_count"] == 0:
        pe.findings.append(FindingDraft("vision.no_references", "No reference pages installed for comparison", "info", "insufficient_evidence", "visual_similarity", 0.9,
                                        "Add reference screenshots to data/references/ to enable visual comparison.", [], ["s0"]))
    else:
        pe.findings.append(FindingDraft("vision.no_similarity", f"No reference page resembles this screenshot (best {best['combined']:.2f} vs threshold {cmp_['threshold']})", "info", "benign", "visual_similarity", 0.4,
                                        f"Compared against {cmp_['reference_count']} reference page(s). Only pages in the reference library can be recognised.", [], ["s0"], {"all_matches": cmp_["matches"]}))
    return pe
