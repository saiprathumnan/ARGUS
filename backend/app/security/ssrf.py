"""SSRF-safe outbound fetching for analyst-submitted URLs.

Rules: http/https only, no embedded credentials, every hostname is resolved and every resolved address
must be public. The TCP connection is then made to the *validated address* (DNS pinning), so a second
lookup cannot return a different (internal) address. Redirects are followed manually and each hop is
re-validated. Response size, time and redirect count are bounded.
"""
import http.client
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urljoin, urlsplit

METADATA_HOSTS = {"169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "metadata", "100.100.100.200"}
_EXTRA_BLOCKED = [ipaddress.ip_network(n) for n in ("100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "64:ff9b::/96")]
ALLOWED_PORTS = {80, 443, 8080, 8443}


class SSRFBlocked(Exception):
    pass


def is_public_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    bad = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    if isinstance(ip, ipaddress.IPv6Address):
        bad = bad or ip.is_site_local
    if bad:
        return False
    return not any(ip in n for n in _EXTRA_BLOCKED)


def default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({i[4][0] for i in infos})


def validate_destination(url: str, resolver: Callable[[str, int], list[str]] = default_resolver) -> tuple[str, str, int, str]:
    """Return (scheme, host, port, pinned_ip) or raise SSRFBlocked."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as e:
        raise SSRFBlocked(f"malformed URL: {e}")
    if parts.scheme not in ("http", "https"):
        raise SSRFBlocked(f"scheme '{parts.scheme}' is not allowed")
    if parts.username or parts.password:
        raise SSRFBlocked("URLs with embedded credentials are not fetched")
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise SSRFBlocked("missing host")
    port = port or (443 if parts.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFBlocked(f"port {port} is not allowed")
    if host in METADATA_HOSTS or host == "localhost" or host.endswith((".localhost", ".internal", ".local")):
        raise SSRFBlocked(f"host '{host}' is a blocked internal name")
    try:
        # Literal IPs, including decimal/hex/octal forms that inet_aton accepts ("2130706433", "0x7f.1").
        literal = None
        try:
            literal = str(ipaddress.ip_address(host))
        except ValueError:
            if re.fullmatch(r"[0-9a-fx.]+", host) and host[0].isdigit():
                try:
                    literal = socket.inet_ntoa(socket.inet_aton(host))
                except OSError:
                    literal = None
        addrs = [literal] if literal else resolver(host, port)
    except (socket.gaierror, OSError) as e:
        raise SSRFBlocked(f"DNS resolution failed: {e}")
    if not addrs:
        raise SSRFBlocked("host did not resolve")
    for a in addrs:
        if not is_public_ip(a):
            raise SSRFBlocked(f"host resolves to non-public address {a}")
    return parts.scheme, host, port, addrs[0]


@dataclass
class Hop:
    url: str
    status: int | None
    ip: str | None
    location: str | None = None


@dataclass
class FetchResult:
    final_url: str
    status: int | None
    hops: list[Hop] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    tls: dict | None = None
    blocked: str | None = None
    error: str | None = None
    fetched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _cert_meta(sock: ssl.SSLSocket) -> dict:
    cert = sock.getpeercert() or {}
    flat = lambda rdns: {k: v for rdn in rdns for (k, v) in rdn}
    return {
        "subject": flat(cert.get("subject", ())), "issuer": flat(cert.get("issuer", ())),
        "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
        "san": [v for (_, v) in cert.get("subjectAltName", ())][:30], "tls_version": sock.version(),
    }


def safe_fetch(url: str, *, timeout: float = 6.0, max_redirects: int = 5, max_bytes: int = 512 * 1024,
               resolver: Callable[[str, int], list[str]] = default_resolver) -> FetchResult:
    result = FetchResult(final_url=url, status=None)
    current = url
    for _ in range(max_redirects + 1):
        try:
            scheme, host, port, ip = validate_destination(current, resolver)
        except SSRFBlocked as e:
            result.blocked = str(e)
            result.hops.append(Hop(current, None, None))
            return result
        parts = urlsplit(current)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn = None
        try:
            raw = socket.create_connection((ip, port), timeout=timeout)  # pinned to validated address
            if scheme == "https":
                ctx = ssl.create_default_context()
                raw = ctx.wrap_socket(raw, server_hostname=host)
                result.tls = _cert_meta(raw)
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.sock = raw
            conn.request("GET", path, headers={"Host": parts.netloc, "User-Agent": "ARGUS-Investigator/1.0", "Accept": "*/*", "Connection": "close"})
            resp = conn.getresponse()
            location = resp.getheader("Location")
            result.hops.append(Hop(current, resp.status, ip, location))
            result.status, result.final_url = resp.status, current
            if resp.status in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                continue
            result.headers = {k.lower(): v for k, v in resp.getheaders()}
            result.body = resp.read(max_bytes)
            return result
        except ssl.SSLError as e:
            result.error = f"TLS error: {e}"
            result.hops.append(Hop(current, None, ip))
            return result
        except (OSError, http.client.HTTPException) as e:
            result.error = f"fetch failed: {type(e).__name__}: {e}"
            result.hops.append(Hop(current, None, ip))
            return result
        finally:
            if conn is not None:
                conn.close()
    result.error = f"more than {max_redirects} redirects"
    return result
