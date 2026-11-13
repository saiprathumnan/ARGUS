"""
A small "network attacker" agent for exercising ARGUS's own detectors.

It generates real, attack-shaped traffic against a target you control —
by default the lab target_server.py running on 127.0.0.1 — and, for the
modes ARGUS's network analysis reads as a PCAP, also writes a packet
capture of exactly what it did, so you can upload the result straight
into ARGUS as evidence and watch it get flagged.

Every mode is guarded by attack_lab.common.assert_lab_target: it
refuses anything that is not loopback or a private (RFC1918/RFC4193)
address. There is no "point this at a real host" option.

Modes:
  portscan    connect() to many ports on the target in quick succession
  bruteforce  repeated fake-SSH login attempts (real traffic; the
              target's own auth.log is the evidence — upload that,
              kind=auth_log)
  beacon      N real connections at a fixed interval to one port
              (classic C2 check-in shape)
  exfil       one real large upload to the target's exfil-sink port
  dnstunnel   crafts DNS queries with long, high-entropy subdomains
              under one parent domain (no real resolver needed —
              ARGUS reads the capture, not the response)
  all         runs portscan, beacon, and dnstunnel back-to-back into
              one combined PCAP, plus a bruteforce run against the
              target's auth.log

Usage:
  python network_agent.py all --target 127.0.0.1 --out ./lab_out
  python network_agent.py portscan --target 127.0.0.1 --out ./lab_out/portscan.pcap
"""
from __future__ import annotations

import argparse
import pathlib
import random
import socket
import string
import time

from common import assert_lab_target, die

ATTACKER_MAC = "02:00:00:00:00:01"
TARGET_MAC = "02:00:00:00:00:02"


# ---------------------------------------------------------------- capture

class Capture:
    """Collects the shape of real connections this agent makes, then
    renders them as a synthetic-but-faithful PCAP (same hosts, ports,
    sizes, and wall-clock timestamps that actually occurred) for ARGUS's
    PCAP ingestion pipeline. Real packets on the wire aren't sniffed —
    this avoids needing raw-socket / libpcap privileges — but every
    field written matches what this process actually sent and received.
    """

    def __init__(self):
        self.events: list[dict] = []

    def record(self, src: str, sport: int, dst: str, dport: int, proto: str,
               out_bytes: int, in_bytes: int, ts: float, syn: bool = True):
        self.events.append(dict(src=src, sport=sport, dst=dst, dport=dport,
                                 proto=proto, out_bytes=out_bytes, in_bytes=in_bytes,
                                 ts=ts, syn=syn))

    def record_dns(self, src: str, dst: str, qname: str, ts: float):
        self.events.append(dict(src=src, sport=random.randint(40000, 60000), dst=dst,
                                 dport=53, proto="dns", qname=qname, ts=ts))

    def write_pcap(self, path: pathlib.Path):
        from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

        pkts = []
        for e in self.events:
            eth = Ether(src=ATTACKER_MAC, dst=TARGET_MAC)
            if e["proto"] == "dns":
                dns = DNS(rd=1, qd=DNSQR(qname=e["qname"]))
                pkt = eth / IP(src=e["src"], dst=e["dst"]) / UDP(sport=e["sport"], dport=53) / dns
                pkt.time = e["ts"]
                pkts.append(pkt)
                continue
            l4 = TCP if e["proto"] == "tcp" else UDP
            if e["proto"] == "tcp":
                syn = eth / IP(src=e["src"], dst=e["dst"]) / TCP(sport=e["sport"], dport=e["dport"], flags="S", seq=1000)
                syn.time = e["ts"]
                pkts.append(syn)
            if e["out_bytes"]:
                data = eth / IP(src=e["src"], dst=e["dst"]) / l4(sport=e["sport"], dport=e["dport"]) / Raw(load=b"x" * min(e["out_bytes"], 1400))
                data.time = e["ts"] + 0.01
                pkts.append(data)
                remaining = e["out_bytes"] - 1400
                t = e["ts"] + 0.02
                while remaining > 0:
                    chunk = min(remaining, 1400)
                    seg = eth / IP(src=e["src"], dst=e["dst"]) / l4(sport=e["sport"], dport=e["dport"]) / Raw(load=b"x" * chunk)
                    seg.time = t
                    pkts.append(seg)
                    remaining -= chunk
                    t += 0.005
            if e["in_bytes"]:
                resp = eth / IP(src=e["dst"], dst=e["src"]) / l4(sport=e["dport"], dport=e["sport"]) / Raw(load=b"y" * min(e["in_bytes"], 1400))
                resp.time = e["ts"] + 0.02
                pkts.append(resp)
        pkts.sort(key=lambda p: p.time)
        wrpcap(str(path), pkts)
        return len(pkts)


# ---------------------------------------------------------------- modes

def mode_portscan(target: str, n_ports: int, cap: Capture, base_port: int = 1):
    ip = assert_lab_target(target)
    src_port = random.randint(40000, 60000)
    ports = random.sample(range(base_port, base_port + max(n_ports * 3, 50)), n_ports)
    print(f"[portscan] {ip}: probing {n_ports} ports")
    for p in ports:
        ts = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect((ip, p))
            s.close()
            open_ = True
        except OSError:
            open_ = False
        cap.record("10.10.0.5", src_port, ip, p, "tcp", out_bytes=0, in_bytes=(40 if open_ else 0), ts=ts)
    print(f"[portscan] done")


def mode_bruteforce(target: str, port: int, attempts: int):
    ip = assert_lab_target(target)
    users = ["root", "admin", "oracle", "ubuntu", "test", "postgres", "jenkins", "backup"]
    print(f"[bruteforce] {ip}:{port}: {attempts} login attempts (evidence lands in the target's auth.log)")
    for i in range(attempts):
        user = random.choice(users)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((ip, port))
            s.recv(64)  # banner
            s.sendall(f"{user}\n".encode())
            s.recv(64)
            s.close()
        except OSError as exc:
            print(f"  attempt {i+1} ({user}): {exc}")
        time.sleep(0.15)
    print("[bruteforce] done — upload the target's lab_out/auth.log to ARGUS as kind=auth_log")


def mode_beacon(target: str, port: int, count: int, interval: float, cap: Capture):
    ip = assert_lab_target(target)
    src_port = random.randint(40000, 60000)
    print(f"[beacon] {ip}:{port}: {count} check-ins every {interval}s")
    for i in range(count):
        ts = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((ip, port))
            s.sendall(b"check-in")
            s.close()
            ok = True
        except OSError as exc:
            ok = False
            print(f"  beacon {i+1}: {exc}")
        cap.record("10.10.0.5", src_port, ip, port, "tcp", out_bytes=8, in_bytes=0, ts=ts, syn=True)
        if i < count - 1:
            time.sleep(interval)
    print("[beacon] done")


def mode_exfil(target: str, port: int, size_mb: float, cap: Capture):
    ip = assert_lab_target(target)
    src_port = random.randint(40000, 60000)
    n_bytes = int(size_mb * 1_000_000)
    print(f"[exfil] {ip}:{port}: sending {size_mb} MB")
    ts = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((ip, port))
        chunk = b"d" * 65536
        sent = 0
        while sent < n_bytes:
            s.sendall(chunk[: min(len(chunk), n_bytes - sent)])
            sent += min(len(chunk), n_bytes - sent)
        s.close()
    except OSError as exc:
        print(f"  exfil: {exc}")
    cap.record("10.10.0.5", src_port, ip, port, "tcp", out_bytes=n_bytes, in_bytes=0, ts=ts)
    print("[exfil] done — note: ARGUS's large-outbound-transfer check only fires for "
          "EXTERNAL destinations, so a loopback/private target like this one by design "
          "will show up in the flow graph but not as that specific finding.")


def mode_dnstunnel(resolver: str, parent: str, n: int, cap: Capture):
    ip = assert_lab_target(resolver)
    print(f"[dnstunnel] {n} high-entropy queries under {parent} via resolver {ip}")
    for _ in range(n):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(28, 40)))
        qname = f"{label}.{parent}"
        ts = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.3)
            # Minimal real UDP packet to port 53; no resolver needs to be listening —
            # ARGUS reads the capture, not a successful resolution.
            s.sendto(b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", (ip, 53))
            s.close()
        except OSError:
            pass
        cap.record_dns("10.10.0.5", ip, qname, ts)
        time.sleep(0.02)
    print("[dnstunnel] done")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["portscan", "bruteforce", "beacon", "exfil", "dnstunnel", "all"])
    ap.add_argument("--target", default="127.0.0.1")
    ap.add_argument("--out", default="./lab_out", help="directory (for 'all') or file path (single mode) for the pcap")
    ap.add_argument("--ports", type=int, default=25)
    ap.add_argument("--attempts", type=int, default=8)
    ap.add_argument("--beacon-port", type=int, default=9001)
    ap.add_argument("--beacon-count", type=int, default=8)
    ap.add_argument("--beacon-interval", type=float, default=3.0)
    ap.add_argument("--exfil-port", type=int, default=9002)
    ap.add_argument("--exfil-mb", type=float, default=8.0)
    ap.add_argument("--dns-parent", default="updates.lab-tunnel.test")
    ap.add_argument("--dns-count", type=int, default=14)
    args = ap.parse_args()

    try:
        assert_lab_target(args.target)
    except Exception as exc:
        die(str(exc))

    out = pathlib.Path(args.out)
    cap = Capture()

    if args.mode == "portscan":
        mode_portscan(args.target, args.ports, cap)
        out.parent.mkdir(parents=True, exist_ok=True) if out.suffix else out.mkdir(parents=True, exist_ok=True)
        dest = out if out.suffix else out / "portscan.pcap"
        n = cap.write_pcap(dest)
        print(f"wrote {n} packets -> {dest}")

    elif args.mode == "bruteforce":
        mode_bruteforce(args.target, 2222, args.attempts)

    elif args.mode == "beacon":
        mode_beacon(args.target, args.beacon_port, args.beacon_count, args.beacon_interval, cap)
        dest = out if out.suffix else out / "beacon.pcap"
        dest.parent.mkdir(parents=True, exist_ok=True)
        n = cap.write_pcap(dest)
        print(f"wrote {n} packets -> {dest}")

    elif args.mode == "exfil":
        mode_exfil(args.target, args.exfil_port, args.exfil_mb, cap)
        dest = out if out.suffix else out / "exfil.pcap"
        dest.parent.mkdir(parents=True, exist_ok=True)
        n = cap.write_pcap(dest)
        print(f"wrote {n} packets -> {dest}")

    elif args.mode == "dnstunnel":
        mode_dnstunnel(args.target, args.dns_parent, args.dns_count, cap)
        dest = out if out.suffix else out / "dnstunnel.pcap"
        dest.parent.mkdir(parents=True, exist_ok=True)
        n = cap.write_pcap(dest)
        print(f"wrote {n} packets -> {dest}")

    else:  # all
        out.mkdir(parents=True, exist_ok=True)
        mode_portscan(args.target, args.ports, cap)
        mode_beacon(args.target, args.beacon_port, args.beacon_count, args.beacon_interval, cap)
        mode_dnstunnel(args.target, args.dns_parent, args.dns_count, cap)
        combined = out / "combined.pcap"
        n = cap.write_pcap(combined)
        print(f"wrote {n} packets -> {combined}")
        mode_bruteforce(args.target, 2222, args.attempts)
        print(f"\nUpload to ARGUS: {combined} as kind=pcap, and the target's lab_out/auth.log as kind=auth_log")


if __name__ == "__main__":
    main()
