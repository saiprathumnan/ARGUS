"""Deterministic email analysis: headers, authentication results, links, attachments, language."""
import email
import email.policy
import hashlib
import html
import re
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from .ioc import extract_iocs, is_private_ip, registered_domain
from .url import BRANDS, skeleton

RISKY_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "hta", "jar", "lnk", "iso", "img", "msi", "com", "pif", "wsf", "chm", "reg"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xll"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "ace", "cab"}
URGENCY = ["urgent", "immediately", "within 24 hours", "within 48 hours", "account will be", "suspended", "suspension", "verify your", "confirm your",
           "unusual activity", "unauthorized", "unauthorised", "action required", "final notice", "limited", "locked", "expire", "click here",
           "click below", "update your payment", "security alert", "reset your password", "avoid closure", "failure to"]
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
RECEIVED_IP = re.compile(r"\[((?:\d{1,3}\.){3}\d{1,3})\]")
HREF_RE = re.compile(r"<a\b[^>]*?href\s*=\s*[\"']?([^\"'\s>]+)[^>]*>(.*?)</a>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def parse_email(data: bytes) -> dict:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    h = lambda name: str(msg.get(name, "") or "").strip()
    from_name, from_addr = parseaddr(h("From"))
    _, reply_to = parseaddr(h("Reply-To"))
    _, return_path = parseaddr(h("Return-Path"))
    to = [a for _, a in getaddresses(msg.get_all("To", []) + msg.get_all("Cc", []))][:20]
    try:
        date = parsedate_to_datetime(h("Date")) if h("Date") else None
    except (TypeError, ValueError):
        date = None
    received = [str(r) for r in msg.get_all("Received", [])]
    received_ips = []
    for r in received:
        for ip in RECEIVED_IP.findall(r):
            if ip not in received_ips:
                received_ips.append(ip)
    auth = {}
    for line in msg.get_all("Authentication-Results", []) + msg.get_all("Received-SPF", []):
        s = str(line)
        for mech, res in AUTH_RE.findall(s):
            auth.setdefault(mech.lower(), res.lower())
        if str(line).lower().lstrip().startswith(("pass", "fail", "softfail", "neutral", "none")) and "spf" not in auth:
            auth["spf"] = s.split()[0].lower()

    text_parts, html_parts, attachments = [], [], []
    is_multipart_body = msg.is_multipart()
    for part in (msg.walk() if is_multipart_body else [msg]):
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:  # malformed transfer encoding: keep going, record nothing for this part
            payload = b""
        if fname or part.get_content_disposition() == "attachment":
            attachments.append({"filename": (fname or "unnamed")[:200], "content_type": ctype, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        elif ctype in ("text/plain", "text/html"):
            charset = part.get_content_charset() or "utf-8"
            try:
                txt = payload.decode(charset, errors="replace")
            except LookupError:
                txt = payload.decode("utf-8", errors="replace")
            (html_parts if ctype == "text/html" else text_parts).append(txt)

    body_html = "\n".join(html_parts)
    body_text = "\n".join(text_parts) or html.unescape(TAG_RE.sub(" ", body_html))
    links = []
    for href, inner in HREF_RE.findall(body_html):
        links.append({"href": html.unescape(href), "text": html.unescape(TAG_RE.sub("", inner)).strip()[:200]})
    known = {l["href"] for l in links}
    shown = " ".join(l["text"] for l in links)  # URLs that are only the visible text of a link are not destinations
    for u in extract_iocs("\n".join(text_parts) if text_parts else body_text)["url"]:
        if u not in known and u not in shown:
            links.append({"href": u, "text": ""})
            known.add(u)
    return {"from_name": from_name, "from_addr": from_addr.lower(), "reply_to": reply_to.lower(), "return_path": return_path.lower(), "to": to,
            "subject": h("Subject"), "date": date, "message_id": h("Message-ID"), "received": received, "received_ips": received_ips, "auth": auth,
            "x_mailer": h("X-Mailer") or h("User-Agent"), "body_text": body_text, "has_html": bool(html_parts), "links": links[:100], "attachments": attachments,
            "header_count": len(msg.keys())}


def detect_email(p: dict) -> list[dict]:
    out = []

    def add(detector, title, severity, confidence, description, indicators=(), classification="suspicious", **details):
        out.append({"detector": detector, "title": title, "severity": severity, "confidence": confidence, "description": description,
                    "indicators": [i for i in indicators if i], "classification": classification, "details": details})

    fd, rd, pd = _domain(p["from_addr"]), _domain(p["reply_to"]), _domain(p["return_path"])
    f_reg, r_reg, p_reg = registered_domain(fd), registered_domain(rd), registered_domain(pd)
    if p["reply_to"] and r_reg and f_reg and r_reg != f_reg:
        add("email.reply_to_mismatch", f"Reply-To domain ({r_reg}) differs from From domain ({f_reg})", "medium", 0.65,
            f"Replies would go to {p['reply_to']} rather than the apparent sender {p['from_addr']}. Common in business-email-compromise and phishing; also used by legitimate mailing platforms.",
            [p["from_addr"], p["reply_to"]], from_addr=p["from_addr"], reply_to=p["reply_to"])
    if p["return_path"] and p_reg and f_reg and p_reg != f_reg:
        add("email.return_path_mismatch", f"Return-Path domain ({p_reg}) differs from From domain ({f_reg})", "low", 0.45,
            "The envelope sender and header sender are in different domains. Frequent with bulk-mail providers, so weak on its own.",
            [p["from_addr"], p["return_path"]], classification="insufficient_evidence", return_path=p["return_path"])
    for mech in ("spf", "dkim", "dmarc"):
        res = p["auth"].get(mech)
        if res in ("fail", "softfail", "permerror"):
            add(f"email.{mech}_fail", f"{mech.upper()} result: {res}", "high" if mech == "dmarc" or res == "fail" else "medium", 0.8,
                f"The receiving server recorded {mech.upper()}={res} for this message, meaning the sender could not be authenticated for {fd or 'the From domain'}. "
                "This result is read from the Authentication-Results header as recorded by the receiving server; ARGUS did not re-evaluate it.",
                [p["from_addr"]], result=res, mechanism=mech)
    if p["auth"] and all(p["auth"].get(m) == "pass" for m in ("spf", "dkim", "dmarc")):
        add("email.auth_pass", "SPF, DKIM and DMARC all pass", "info", 0.6,
            f"The receiving server recorded spf=pass, dkim=pass and dmarc=pass for {fd}. This authenticates the sending domain; it says nothing about the sender's intent.",
            [p["from_addr"]], classification="benign")
    if not p["auth"]:
        add("email.no_auth_results", "No SPF/DKIM/DMARC results present in headers", "info", 0.3,
            "The message carries no Authentication-Results header, so sender authentication cannot be assessed from this evidence.", classification="insufficient_evidence")
    name_l = (p["from_name"] or "").lower()
    m = re.search(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", name_l)
    if m and _domain(m.group(0)) != fd:
        add("email.display_name_spoof", "Display name contains a different email address than the real sender", "high", 0.8,
            f"Display name shows '{p['from_name']}' while the actual address is {p['from_addr']}.", [p["from_addr"]], display_name=p["from_name"])
    for brand, legit in BRANDS.items():
        if len(brand) >= 5 and brand in skeleton(re.sub(r"[^a-z0-9а-яα-ω]", "", name_l)) and f_reg and f_reg not in legit:
            add("email.brand_display_name", f"Display name references '{brand}' but sender domain is {f_reg}", "medium", 0.6,
                f"The display name '{p['from_name']}' invokes the brand '{brand}', whose known domains are {', '.join(sorted(legit))}; the message was sent from {p['from_addr']}.",
                [p["from_addr"]], brand=brand, display_name=p["from_name"])
            break
    mid_dom = registered_domain(_domain(p["message_id"].strip("<>")))
    if mid_dom and f_reg and mid_dom != f_reg and mid_dom != p_reg:
        add("email.message_id_mismatch", f"Message-ID domain ({mid_dom}) does not match sender domain ({f_reg})", "low", 0.35,
            "Header inconsistency. Many relays rewrite Message-ID, so this is supporting context only.", classification="insufficient_evidence", message_id=p["message_id"])
    public_hops = [ip for ip in p["received_ips"] if not is_private_ip(ip)]
    text = (p["subject"] + " " + p["body_text"]).lower()
    hits = [u for u in URGENCY if u in text]
    if len(hits) >= 3:
        add("email.phishing_language", f"Urgency / credential-themed language ({len(hits)} phrases)", "medium", 0.55,
            "The message uses pressure phrases typical of phishing: " + ", ".join(f"'{x}'" for x in hits[:8]) + ". Keyword evidence only; legitimate notices use similar wording.",
            matched_phrases=hits[:12])
    for l in p["links"]:
        shown = re.search(r"(?:https?://)?((?:[a-z0-9\-]+\.)+[a-z]{2,})", l["text"].lower())
        href_host = re.sub(r"^[a-z]+://", "", l["href"].lower()).split("/")[0].split(":")[0].split("@")[-1]
        if shown and registered_domain(shown.group(1)) and registered_domain(href_host) and registered_domain(shown.group(1)) != registered_domain(href_host):
            add("email.link_text_mismatch", f"Link text shows {shown.group(1)} but points to {href_host}", "high", 0.85,
                f"The visible link text '{l['text'][:80]}' displays the domain {shown.group(1)}, while the actual destination is {l['href'][:200]}.",
                [l["href"]], displayed=shown.group(1), actual=l["href"])
    for a in p["attachments"]:
        parts = a["filename"].lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if len(parts) >= 3 and ext in RISKY_EXT:
            add("email.attachment_double_extension", f"Attachment with disguised executable extension: {a['filename']}", "high", 0.85,
                f"'{a['filename']}' uses a double extension ending in .{ext}. ARGUS hashed the attachment (SHA-256 {a['sha256']}) and did not execute it.",
                [a["sha256"]], **a)
        elif ext in RISKY_EXT:
            add("email.attachment_executable", f"Executable/script attachment: {a['filename']}", "high", 0.7,
                f"Attachment type .{ext} can run code when opened. SHA-256 {a['sha256']}. Not executed by ARGUS.", [a["sha256"]], **a)
        elif ext in MACRO_EXT:
            add("email.attachment_macro_document", f"Macro-enabled Office attachment: {a['filename']}", "medium", 0.6,
                f"Macro-enabled format .{ext}. SHA-256 {a['sha256']}. Macro content was not analysed.", [a["sha256"]], **a)
        elif ext in ARCHIVE_EXT:
            add("email.attachment_archive", f"Archive attachment: {a['filename']}", "low", 0.3,
                "Archives can conceal other file types; contents were not unpacked.", [a["sha256"]], classification="insufficient_evidence", **a)
    return out, public_hops
