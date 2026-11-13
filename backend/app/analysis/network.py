"""Network capture analysis (Scapy). Aggregates packets into client->server flows, extracts DNS/HTTP/TLS
metadata and runs deterministic detections. Packets are parsed, never replayed or executed."""
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .ioc import is_private_ip
from .url import shannon_entropy

COMMON_PORTS = {20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139, 143, 161, 389, 443, 445, 465, 587, 636, 853, 993, 995, 1900, 3389, 5353, 8080, 8443}
KNOWN_BAD_PORTS = {4444: "Metasploit default handler", 1337: "common backdoor port", 31337: "Back Orifice / common backdoor port",
                   6667: "IRC (historic botnet C2)", 6697: "IRC over TLS", 9001: "Tor ORPort", 9050: "Tor SOCKS", 5555: "ADB / common RAT port", 12345: "NetBus"}
MAX_PACKETS = 300_000


@dataclass
class Flow:
    client: str
    server: str
    port: int
    proto: str
    starts: list = field(default_factory=list)   # connection start times (TCP SYN / UDP session start)
    sizes_out: list = field(default_factory=list)
    sizes_in: list = field(default_factory=list)
    first: float = 0.0
    last: float = 0.0
    last_out: float = -1e18
    first_packet_no: int = 0
    sni: str | None = None
    http_host: str | None = None
    http_paths: list = field(default_factory=list)

    def key(self) -> str:
        return f"{self.client}>{self.server}:{self.port}/{self.proto}"


def port_rarity(port: int) -> int:
    return 0 if port in COMMON_PORTS else (1 if port < 49152 else 2)


def flow_features(flow: Flow, src_unique_dports: int) -> dict:
    """Feature vector shared by the anomaly model's training and inference paths."""
    starts = sorted(flow.starts)
    intervals = [b - a for a, b in zip(starts, starts[1:])]
    sizes = flow.sizes_out + flow.sizes_in
    mean_iv = statistics.fmean(intervals) if intervals else 0.0
    cv = (statistics.pstdev(intervals) / mean_iv) if len(intervals) >= 2 and mean_iv > 0 else 1.0
    b_out, b_in = sum(flow.sizes_out), sum(flow.sizes_in)
    return {
        "conn_count": math.log1p(len(starts)),
        "duration_s": math.log1p(max(flow.last - flow.first, 0.0)),
        "bytes_out": math.log1p(b_out),
        "bytes_in": math.log1p(b_in),
        "out_in_ratio": math.log((b_out + 1) / (b_in + 1)),
        "mean_pkt_size": statistics.fmean(sizes) if sizes else 0.0,
        "std_pkt_size": statistics.pstdev(sizes) if len(sizes) > 1 else 0.0,
        "interval_mean": math.log1p(mean_iv),
        "interval_cv": min(cv, 5.0),
        "port_rarity": float(port_rarity(flow.port)),
        "src_unique_dports": math.log1p(src_unique_dports),
        # regularity weighted by repetition: high only for many evenly spaced connections
        "periodicity": math.log1p(len(starts)) * (1.0 - min(cv, 1.0)),
    }


FEATURE_NAMES = ["conn_count", "duration_s", "bytes_out", "bytes_in", "out_in_ratio", "mean_pkt_size", "std_pkt_size",
                 "interval_mean", "interval_cv", "port_rarity", "src_unique_dports", "periodicity"]


def _sni_from_client_hello(payload: bytes) -> str | None:
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        p = 43
        p += 1 + payload[p]                                   # session id
        p += 2 + int.from_bytes(payload[p:p + 2], "big")       # cipher suites
        p += 1 + payload[p]                                   # compression
        end = p + 2 + int.from_bytes(payload[p:p + 2], "big")
        p += 2
        while p + 4 <= min(end, len(payload)):
            etype = int.from_bytes(payload[p:p + 2], "big")
            elen = int.from_bytes(payload[p + 2:p + 4], "big")
            if etype == 0:
                nlen = int.from_bytes(payload[p + 7:p + 9], "big")
                return payload[p + 9:p + 9 + nlen].decode("ascii", "ignore").lower() or None
            p += 4 + elen
    except (IndexError, ValueError):
        return None
    return None


def parse_pcap(path: str) -> dict:
    """Return {'flows': {key: Flow}, 'dns': [...], 'packet_count', 'truncated', 'first_ts', 'last_ts', 'protocols'}."""
    from scapy.all import DNS, IP, TCP, UDP, IPv6, PcapReader, Raw  # imported lazily: scapy import is slow

    flows: dict[tuple, Flow] = {}
    dns_queries: dict[tuple, dict] = {}
    protocols: dict[str, int] = defaultdict(int)
    n = 0
    first_ts = last_ts = None
    truncated = False
    with PcapReader(path) as reader:
        for pkt in reader:
            n += 1
            if n > MAX_PACKETS:
                truncated = True
                break
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                protocols["non-ip"] += 1
                continue
            ts = float(pkt.time)
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
            l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
            if l4 is None:
                protocols["other-ip"] += 1
                continue
            proto = "tcp" if pkt.haslayer(TCP) else "udp"
            protocols[proto] += 1
            sport, dport, src, dst = int(l4.sport), int(l4.dport), str(ip.src), str(ip.dst)
            size = len(pkt)
            fwd, rev = (src, dst, dport, proto), (dst, src, sport, proto)
            is_syn = proto == "tcp" and (int(l4.flags) & 0x12) == 0x02
            if fwd in flows:
                k, outbound = fwd, True
            elif rev in flows:
                k, outbound = rev, False
            else:
                # New flow. Initiator = SYN sender; otherwise assume the lower / well-known port is the server.
                if is_syn or dport in COMMON_PORTS or (sport not in COMMON_PORTS and dport <= sport):
                    k, outbound = fwd, True
                else:
                    k, outbound = rev, False
                flows[k] = Flow(client=k[0], server=k[1], port=k[2], proto=proto, first=ts, last=ts, first_packet_no=n)
            f = flows[k]
            f.last = max(f.last, ts)
            if outbound:
                f.sizes_out.append(size)
                if is_syn or (proto == "udp" and ts - f.last_out > 1.0) or (proto == "tcp" and not f.starts):
                    f.starts.append(ts)
                f.last_out = ts
            else:
                f.sizes_in.append(size)
            if pkt.haslayer(DNS):
                d = pkt.getlayer(DNS)
                try:
                    if d.qd is not None and d.qdcount:
                        qname = d.qd.qname.decode("ascii", "ignore").rstrip(".").lower()
                        qk = (src if d.qr == 0 else dst, qname)
                        rec = dns_queries.setdefault(qk, {"client": qk[0], "qname": qname, "count": 0, "first": ts, "last": ts, "answers": set(), "packet_no": n, "resolver": dst if d.qr == 0 else src})
                        if d.qr == 0:
                            rec["count"] += 1
                            rec["last"] = max(rec["last"], ts)
                        else:
                            for i in range(min(int(d.ancount or 0), 20)):
                                rr = d.an[i]
                                if getattr(rr, "type", None) in (1, 28):
                                    rec["answers"].add(str(rr.rdata))
                except (AttributeError, IndexError, UnicodeError):
                    pass
            elif outbound and pkt.haslayer(Raw) and proto == "tcp":
                payload = bytes(pkt[Raw].load)[:2048]
                if f.sni is None and payload[:1] == b"\x16":
                    f.sni = _sni_from_client_hello(payload)
                elif payload[:5] in (b"GET /", b"POST ", b"HEAD ", b"PUT /"):
                    try:
                        lines = payload.split(b"\r\n")
                        req = lines[0].decode("ascii", "ignore").split(" ")
                        for line in lines[1:12]:
                            if line.lower().startswith(b"host:"):
                                f.http_host = line[5:].strip().decode("ascii", "ignore").lower()
                        if len(req) >= 2 and len(f.http_paths) < 10:
                            f.http_paths.append(f"{req[0]} {req[1][:200]}")
                    except (IndexError, UnicodeError):
                        pass
    return {"flows": {f.key(): f for f in flows.values()}, "dns": [dict(v, answers=sorted(v["answers"])) for v in dns_queries.values()],
            "packet_count": min(n, MAX_PACKETS), "truncated": truncated, "first_ts": first_ts, "last_ts": last_ts, "protocols": dict(protocols)}


def ts_dt(ts: float | None) -> datetime | None:
    return datetime.fromtimestamp(ts, tz=timezone.utc) if ts is not None else None


def detect_network(parsed: dict) -> list[dict]:
    """Deterministic detections. Each returns flow keys / qnames so findings stay tied to captured packets."""
    out = []
    flows: dict[str, Flow] = parsed["flows"]
    by_client_server: dict[tuple, set] = defaultdict(set)
    for f in flows.values():
        by_client_server[(f.client, f.server)].add(f.port)

    for f in flows.values():
        starts = sorted(f.starts)
        intervals = [b - a for a, b in zip(starts, starts[1:])]
        external = not is_private_ip(f.server)
        if len(starts) >= 6 and f.port not in (123, 53, 67, 5353, 1900):
            mean_iv = statistics.fmean(intervals)
            cv = statistics.pstdev(intervals) / mean_iv if mean_iv > 0 else 9
            if mean_iv >= 1.0 and cv < 0.15:
                rare = port_rarity(f.port) > 0
                out.append({"detector": "network.beaconing", "severity": "high" if (rare and external) else "medium", "confidence": 0.75 if external else 0.55,
                            "title": f"Periodic connections from {f.client} to {f.server}:{f.port} every ~{mean_iv:.0f}s",
                            "description": f"{len(starts)} connection starts with mean interval {mean_iv:.1f}s and coefficient of variation {cv:.3f}. "
                                           "Highly regular timing is consistent with automated check-ins (possible command-and-control beaconing), "
                                           "but also with legitimate polling software; the destination must be identified before concluding.",
                            "flows": [f.key()], "indicators": [f.client, f.server],
                            "details": {"connections": len(starts), "interval_mean_s": round(mean_iv, 2), "interval_cv": round(cv, 4), "port": f.port, "external_destination": external}})
        if f.port in KNOWN_BAD_PORTS and (f.sizes_in or len(starts) >= 2):
            out.append({"detector": "network.suspicious_port", "severity": "medium", "confidence": 0.5,
                        "title": f"Traffic to port {f.port} on {f.server} ({KNOWN_BAD_PORTS[f.port]})",
                        "description": f"{f.client} exchanged {len(f.sizes_out) + len(f.sizes_in)} packets with {f.server}:{f.port}/{f.proto}. "
                                       f"Port {f.port} is associated with: {KNOWN_BAD_PORTS[f.port]}. A port number alone does not identify the application.",
                        "flows": [f.key()], "indicators": [f.client, f.server], "details": {"port": f.port, "association": KNOWN_BAD_PORTS[f.port]}})
        b_out, b_in = sum(f.sizes_out), sum(f.sizes_in)
        if external and b_out >= 5_000_000 and b_out > 10 * (b_in + 1):
            out.append({"detector": "network.large_outbound_transfer", "severity": "high", "confidence": 0.6,
                        "title": f"Large outbound transfer: {b_out / 1e6:.1f} MB from {f.client} to {f.server}:{f.port}",
                        "description": f"Outbound volume {b_out} bytes versus {b_in} bytes inbound ({b_out / (b_in + 1):.0f}:1). "
                                       "Upload-dominant flows to external hosts can indicate data exfiltration; backups and uploads look identical at this layer.",
                        "flows": [f.key()], "indicators": [f.client, f.server], "details": {"bytes_out": b_out, "bytes_in": b_in}})

    for (client, server), ports in by_client_server.items():
        if len(ports) >= 15:
            keys = [f.key() for f in flows.values() if f.client == client and f.server == server]
            out.append({"detector": "network.port_scan", "severity": "medium", "confidence": 0.7,
                        "title": f"{client} contacted {len(ports)} distinct ports on {server}",
                        "description": f"Connections to {len(ports)} different destination ports on one host is characteristic of port scanning.",
                        "flows": keys[:50], "indicators": [client, server], "details": {"distinct_ports": len(ports), "sample_ports": sorted(ports)[:25]}})

    per_client_dns: dict[str, list] = defaultdict(list)
    for q in parsed["dns"]:
        per_client_dns[q["client"]].append(q)
    for client, qs in per_client_dns.items():
        by_parent: dict[str, list] = defaultdict(list)
        for q in qs:
            labels = q["qname"].split(".")
            if len(labels) >= 3:
                by_parent[".".join(labels[-2:])].append(q)
        for parent, items in by_parent.items():
            subs = [i["qname"][: -len(parent) - 1] for i in items]
            long_high = [s for s in subs if len(s) >= 24 and shannon_entropy(s.replace(".", "")) >= 3.5]
            if len(set(subs)) >= 10 and len(long_high) >= 0.6 * len(subs):
                out.append({"detector": "network.dns_tunneling_pattern", "severity": "high", "confidence": 0.65,
                            "title": f"{len(set(subs))} long, high-entropy DNS subdomains under {parent} from {client}",
                            "description": "Many unique long random-looking subdomains under one parent domain is the query pattern produced by DNS tunnelling "
                                           "and some DGA malware. Certain CDNs and telemetry services produce similar queries.",
                            "qnames": [i["qname"] for i in items][:30], "indicators": [client] + [i["qname"] for i in items][:5],
                            "details": {"unique_subdomains": len(set(subs)), "mean_label_length": round(statistics.fmean(len(s) for s in subs), 1), "parent_domain": parent}})
    return out
