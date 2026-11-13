"""Indicator-of-compromise extraction from untrusted text."""
import ipaddress
import re

import tldextract

# Bundled public-suffix snapshot only: never fetches the list from the network.
# RFC 2606 / 6761 reserved TLDs are treated as suffixes so documentation domains parse like real ones.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, extra_suffixes=["example", "test", "invalid"])

URL_RE = re.compile(r"\b(?:https?|hxxps?|ftp)://[^\s<>\"'\)\]\}]+", re.I)
IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9\-]{1,23}\b", re.I)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
FILE_EXT_LIKE = {"exe", "dll", "txt", "log", "png", "jpg", "pdf", "doc", "docx", "js", "ps1", "bat", "zip", "html", "htm", "php", "py", "json", "xml", "so", "conf", "service", "tmp", "dat", "bin"}


def refang(text: str) -> str:
    return (text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("hxxp", "http").replace("hXXp", "http"))


def registered_domain(host: str) -> str:
    e = _extract(host or "")
    return f"{e.domain}.{e.suffix}".lower() if e.domain and e.suffix else ""


def split_host(host: str):
    e = _extract(host or "")
    return e.subdomain.lower(), e.domain.lower(), e.suffix.lower()


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                                                        "0.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "::/128")]


def is_private_ip(value: str) -> bool:
    """True for addresses that are internal to a network (RFC 1918, loopback, link-local, CGNAT, ULA, multicast).

    Deliberately NOT ipaddress.is_private: that also covers documentation ranges (RFC 5737), which ARGUS's
    sample data uses to stand in for internet hosts. For the SSRF guard, see security/ssrf.py (stricter).
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in n for n in _INTERNAL_NETS if n.version == ip.version)


def valid_domain(candidate: str) -> bool:
    c = candidate.lower().strip(".")
    sub, dom, suf = split_host(c)
    if not dom or not suf:
        return False
    if suf.split(".")[-1] in FILE_EXT_LIKE and not sub:
        return False  # "report.pdf", "cmd.exe" are filenames, not domains
    return True


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Return de-duplicated indicators in order of first appearance."""
    text = refang(text or "")
    out: dict[str, list[str]] = {"url": [], "ip": [], "domain": [], "email": [], "sha256": []}

    def add(kind, value):
        if value not in out[kind]:
            out[kind].append(value)

    for m in URL_RE.finditer(text):
        add("url", m.group(0).rstrip(".,;:!?'\""))
    for m in EMAIL_RE.finditer(text):
        add("email", m.group(0).lower())
    for m in IPV4_RE.finditer(text):
        add("ip", m.group(0))
    for m in SHA256_RE.finditer(text):
        add("sha256", m.group(0).lower())
    for m in DOMAIN_RE.finditer(text):
        d = m.group(0).lower()
        if not is_ip(d) and valid_domain(d):
            add("domain", d)
    return out
