"""
Shared guard for the ARGUS attack lab.

Every script in this folder refuses to touch anything outside loopback
or RFC1918 private ranges. This is a test-bench for exercising ARGUS's
own network detectors against traffic you generate on your own machine
or lab network — it is not a general-purpose attack tool, and it will
not run against a public address.
"""
from __future__ import annotations

import ipaddress
import socket
import sys


class NotALabTarget(ValueError):
    pass


def resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError as exc:
        raise NotALabTarget(f"could not resolve {host!r}: {exc}") from exc


def assert_lab_target(host: str) -> str:
    """Resolve `host` and raise unless it is loopback or RFC1918 private.

    Returns the resolved IP string on success. This is the single choke
    point every attack-mode function in network_agent.py goes through
    before it opens a socket.
    """
    ip_str = resolve(host)
    ip = ipaddress.ip_address(ip_str)
    if ip.is_loopback:
        return ip_str
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("0.0.0.0/8"):
        raise NotALabTarget(f"{host} ({ip_str}) is not a usable lab target")
    if ip.is_private and not ip.is_link_local and not ip.is_multicast:
        return ip_str
    raise NotALabTarget(
        f"refusing to target {host} ({ip_str}): not loopback or a private "
        f"(RFC1918/RFC4193) address. This lab only ever points at hosts "
        f"you run yourself on 127.0.0.1 or your own private LAN/VM."
    )


def die(msg: str) -> None:
    print(f"[attack_lab] {msg}", file=sys.stderr)
    sys.exit(1)
