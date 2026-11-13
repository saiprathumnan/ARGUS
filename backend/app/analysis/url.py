"""Deterministic URL analysis. Produces structural indicators only; it never declares a URL malicious."""
import math
import re
import unicodedata
from collections import Counter
from urllib.parse import parse_qs, unquote, urlsplit

from .ioc import is_ip, registered_domain, split_host

SUSPICIOUS_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "country", "kim", "work", "rest",
                   "fit", "loan", "men", "buzz", "cam", "icu", "cyou", "quest", "sbs", "monster", "support", "live"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
              "rb.gy", "t.ly", "tiny.cc", "lnkd.in", "s.id", "v.gd", "bl.ink", "short.io"}
SUSPICIOUS_TOKENS = ["login", "signin", "sign-in", "verify", "verification", "secure", "account", "update", "confirm", "banking",
                     "password", "credential", "wallet", "unlock", "suspended", "billing", "invoice", "webscr", "authenticate", "recover"]
# Brand -> legitimate registered domains. Used for look-alike detection; editable in data/brands.json.
BRANDS = {
    "paypal": {"paypal.com", "paypal.me"}, "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com"},
    "office365": {"office.com", "microsoft.com"}, "outlook": {"outlook.com", "live.com"}, "google": {"google.com", "gmail.com", "youtube.com"},
    "apple": {"apple.com", "icloud.com"}, "icloud": {"icloud.com", "apple.com"}, "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"},
    "netflix": {"netflix.com"}, "facebook": {"facebook.com", "fb.com", "meta.com"}, "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"}, "linkedin": {"linkedin.com"}, "dropbox": {"dropbox.com"}, "docusign": {"docusign.com", "docusign.net"},
    "github": {"github.com"}, "adobe": {"adobe.com"}, "dhl": {"dhl.com"}, "fedex": {"fedex.com"}, "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"}, "sbi": {"sbi.co.in", "onlinesbi.sbi"}, "chase": {"chase.com"}, "wellsfargo": {"wellsfargo.com"},
    "coinbase": {"coinbase.com"}, "binance": {"binance.com"}, "steam": {"steampowered.com", "steamcommunity.com"},
}
# Common confusable characters -> ASCII skeleton
CONFUSABLES = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l",
                             "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d",
                             "ɡ": "g", "ո": "n", "ս": "u", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "α": "a", "ι": "i", "κ": "k"})


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def damerau_levenshtein(a: str, b: str) -> int:
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def skeleton(label: str) -> str:
    try:
        if label.startswith("xn--"):
            label = label.encode("ascii").decode("idna")
    except UnicodeError:
        pass
    label = unicodedata.normalize("NFKC", label).lower().translate(CONFUSABLES)
    return label.replace("rn", "m").replace("vv", "w")


def normalise_url(raw: str) -> str:
    u = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", u):
        u = "http://" + u
    return u


def brand_lookalike(host: str) -> list[dict]:
    """Return look-alike observations for a hostname. Legitimate brand domains never match."""
    reg = registered_domain(host)
    sub, dom, _ = split_host(host)
    hits = []
    labels = [l for l in re.split(r"[.\-_]", f"{sub}.{dom}") if l]
    dom_skel = skeleton(dom)
    for brand, legit in BRANDS.items():
        if reg in legit:
            return []
    for brand, legit in BRANDS.items():
        if dom == brand:
            hits.append({"brand": brand, "kind": "brand_on_unofficial_tld", "detail": f"'{dom}' used outside the brand's known domains ({', '.join(sorted(legit))})"})
            continue
        dist = damerau_levenshtein(dom, brand)
        if len(brand) >= 5 and 0 < dist <= (1 if len(brand) < 8 else 2) and abs(len(dom) - len(brand)) <= 2:
            hits.append({"brand": brand, "kind": "typosquat", "detail": f"registered label '{dom}' is edit-distance {dist} from '{brand}'"})
        elif dom_skel == brand and dom != brand:
            hits.append({"brand": brand, "kind": "homoglyph", "detail": f"'{dom}' normalises to '{brand}' after confusable-character folding"})
        elif any(skeleton(l) == brand for l in labels) or (len(brand) >= 6 and brand in dom_skel):
            hits.append({"brand": brand, "kind": "brand_in_hostname", "detail": f"brand token '{brand}' appears in host '{host}' whose registered domain is '{reg}'"})
    seen, uniq = set(), []
    for h in hits:
        if h["brand"] not in seen:
            seen.add(h["brand"])
            uniq.append(h)
    return uniq


def analyse_url(raw: str) -> dict:
    """Return {'url','host','registered_domain','signals':[{id,weight,detail}], 'score'}."""
    url = normalise_url(raw)
    signals: list[dict] = []

    def sig(id_, weight, detail):
        signals.append({"id": id_, "weight": weight, "detail": detail})

    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError as e:
        return {"url": url, "host": "", "registered_domain": "", "signals": [{"id": "malformed_url", "weight": 2, "detail": str(e)}], "score": 2, "valid": False}
    if not host:
        return {"url": url, "host": "", "registered_domain": "", "signals": [{"id": "malformed_url", "weight": 2, "detail": "no host component"}], "score": 2, "valid": False}

    reg = registered_domain(host)
    sub, dom, suffix = split_host(host)
    path_q = unquote(parts.path + ("?" + parts.query if parts.query else ""))

    if is_ip(host) or re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host):
        sig("ip_host", 3, f"host is a raw IP address ({host}) rather than a domain name")
    elif not reg:
        sig("unregistered_suffix", 1, f"host '{host}' has no recognised public suffix")
    if parts.username or "@" in parts.netloc:
        sig("userinfo_in_url", 3, "URL contains user-info before '@', which can disguise the real host")
    tld = suffix.split(".")[-1] if suffix else ""
    if tld in SUSPICIOUS_TLDS:
        sig("suspicious_tld", 1, f"top-level domain '.{tld}' is frequently abused in phishing campaigns")
    if reg in SHORTENERS:
        sig("url_shortener", 2, f"'{reg}' is a URL shortening service; the destination is hidden")
    if "xn--" in host:
        sig("punycode", 2, "hostname contains punycode (internationalised) labels")
    if any(ord(c) > 127 for c in host):
        scripts = {unicodedata.name(c, "?").split(" ")[0] for c in host if c.isalpha()}
        if len(scripts) > 1:
            sig("mixed_script", 3, f"hostname mixes scripts: {', '.join(sorted(scripts))}")
    for hit in brand_lookalike(host):
        sig(hit["kind"], 3 if hit["kind"] in ("typosquat", "homoglyph") else 2, hit["detail"])
    n_sub = len([s for s in sub.split(".") if s]) if sub else 0
    if n_sub >= 3:
        sig("many_subdomains", 1, f"{n_sub} subdomain levels")
    if port and port not in (80, 443):
        sig("non_standard_port", 1, f"non-standard port {port}")
    if len(url) > 100:
        sig("long_url", 1, f"URL length {len(url)}")
    tokens = [t for t in SUSPICIOUS_TOKENS if t in (host + path_q).lower()]
    if len(tokens) >= 2:
        sig("credential_keywords", 2, f"credential-themed tokens: {', '.join(tokens[:6])}")
    elif tokens:
        sig("credential_keyword", 1, f"credential-themed token: {tokens[0]}")
    if dom and len(dom) >= 12 and shannon_entropy(dom) > 3.6 and sum(c.isdigit() for c in dom) >= 3:
        sig("random_looking_domain", 1, f"domain label '{dom}' has high character entropy ({shannon_entropy(dom):.2f})")
    if dom.count("-") >= 3:
        sig("hyphenated_domain", 1, f"domain label contains {dom.count('-')} hyphens")
    if re.search(r"https?://|www\.[a-z0-9\-]+\.[a-z]{2,}", path_q, re.I) or any(k in parse_qs(parts.query) for k in ("url", "redirect", "redir", "next", "target", "dest", "continue", "goto")):
        sig("embedded_redirect", 1, "path or query embeds another URL or an open-redirect style parameter")
    if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|ps1|hta|jar|lnk)($|\?)", path_q, re.I):
        sig("double_extension", 3, "path ends with a double extension that disguises an executable type")
    elif re.search(r"\.(exe|scr|vbs|bat|cmd|ps1|hta|jar|lnk|iso|msi)($|\?)", parts.path, re.I):
        sig("executable_download", 1, "path points directly at an executable or script file type")
    if parts.scheme == "http" and tokens:
        sig("cleartext_credentials_page", 1, "credential-themed page served over plain HTTP")
    if url.count("%") >= 8:
        sig("heavy_percent_encoding", 1, f"{url.count('%')} percent-encoded sequences")

    return {"url": url, "host": host, "registered_domain": reg, "scheme": parts.scheme, "port": port, "path": parts.path,
            "signals": signals, "score": sum(s["weight"] for s in signals), "valid": True}


def classify_score(score: int) -> tuple[str, str, float]:
    """(classification, severity, confidence) from a structural score. Structure alone never confirms maliciousness."""
    if score >= 6:
        return "suspicious", "high", 0.8
    if score >= 3:
        return "suspicious", "medium", 0.6
    if score >= 1:
        return "insufficient_evidence", "low", 0.35
    return "benign", "info", 0.5
