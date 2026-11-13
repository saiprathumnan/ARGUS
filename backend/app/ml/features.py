"""Lexical URL features for the phishing classifier.

Deliberately excluded to avoid dataset leakage / era bias (see docs/ARCHITECTURE.md, ADR-006):
  * the scheme (http vs https) - in the training corpus it is a collection artefact, not a property of phishing
  * a leading "www." label - same reason
Features are computed on the scheme-less, www-less URL so training and inference see identical input.
"""
import re
from urllib.parse import urlsplit

from ..analysis.ioc import is_ip, split_host
from ..analysis.url import SHORTENERS, SUSPICIOUS_TLDS, SUSPICIOUS_TOKENS, shannon_entropy

FEATURES = ["url_length", "host_length", "path_length", "query_length", "num_dots_host", "num_subdomains", "num_hyphens_host",
            "num_digits_host", "digit_ratio_url", "num_slashes", "num_special", "num_params", "has_at", "has_ip_host",
            "host_entropy", "path_entropy", "suspicious_token_count", "suspicious_tld", "is_shortener", "tld_length",
            "domain_length", "longest_host_label", "longest_path_token", "num_path_segments", "has_port", "num_percent",
            "brand_token_outside_domain", "has_file_ext_php_html", "vowel_ratio_domain"]
_BRAND_TOKENS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook", "ebay", "bank", "outlook", "office", "dropbox", "icloud", "chase", "wellsfargo", "alibaba", "adobe", "dhl", "yahoo"]


def canonical(url: str) -> str:
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", url.strip())
    return re.sub(r"^www\.", "", u, flags=re.I)


def extract_features(url: str) -> dict:
    u = canonical(url)
    try:
        parts = urlsplit("http://" + u)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        parts, host, port = urlsplit("http://invalid.invalid/"), "", None
    path, query = parts.path or "", parts.query or ""
    sub, dom, suffix = split_host(host)
    labels = [l for l in host.split(".") if l]
    path_tokens = [t for t in re.split(r"[/\-_.=&?]", path + "?" + query) if t]
    rest = (sub + path + query).lower()
    low = u.lower()
    return {
        "url_length": len(u), "host_length": len(host), "path_length": len(path), "query_length": len(query),
        "num_dots_host": host.count("."), "num_subdomains": len([s for s in sub.split(".") if s]),
        "num_hyphens_host": host.count("-"), "num_digits_host": sum(c.isdigit() for c in host),
        "digit_ratio_url": sum(c.isdigit() for c in u) / max(len(u), 1), "num_slashes": u.count("/"),
        "num_special": sum(u.count(c) for c in "@!$&*~;=+,"), "num_params": len([p for p in query.split("&") if p]),
        "has_at": int("@" in u), "has_ip_host": int(is_ip(host)), "host_entropy": shannon_entropy(host),
        "path_entropy": shannon_entropy(path), "suspicious_token_count": sum(t in low for t in SUSPICIOUS_TOKENS),
        "suspicious_tld": int(suffix.split(".")[-1] in SUSPICIOUS_TLDS) if suffix else 0,
        "is_shortener": int(f"{dom}.{suffix}" in SHORTENERS), "tld_length": len(suffix), "domain_length": len(dom),
        "longest_host_label": max((len(l) for l in labels), default=0), "longest_path_token": max((len(t) for t in path_tokens), default=0),
        "num_path_segments": len([s for s in path.split("/") if s]), "has_port": int(port is not None), "num_percent": u.count("%"),
        "brand_token_outside_domain": int(any(b in rest for b in _BRAND_TOKENS)),
        "has_file_ext_php_html": int(bool(re.search(r"\.(php|html?|asp|aspx|jsp)$", path.lower()))),
        "vowel_ratio_domain": sum(c in "aeiou" for c in dom) / max(len(dom), 1),
    }


def vectorise(url: str) -> list[float]:
    f = extract_features(url)
    return [float(f[n]) for n in FEATURES]
