"""Synthetic, labelled network-flow generator used to train and evaluate the anomaly model.

No public PCAP corpus is bundled (size and licensing), so the baseline is generated. Every generated
flow goes through the *same* Flow -> flow_features path as real captures, so the model sees identical
feature semantics at training and inference time. This is documented as a limitation: the model learns
what THIS generator considers normal, not what your network considers normal. Retrain on your own
benign captures with `python -m app.ml.train_anomaly --pcap-dir <dir>`.
"""
import random

from ..analysis.network import Flow

BENIGN_PROFILES = ["web", "web", "web", "web", "dns", "dns", "ntp", "mail", "ssh_admin", "update_poll", "video", "custom_app"]
ANOMALY_PROFILES = ["beacon", "exfil", "scan_probe", "odd_port_interactive"]


def _flow(rng, client, server, port, proto, starts, out_sizes, in_sizes):
    f = Flow(client=client, server=server, port=port, proto=proto)
    f.starts = sorted(starts)
    f.sizes_out, f.sizes_in = out_sizes, in_sizes
    f.first = f.starts[0]
    f.last = f.starts[-1] + rng.uniform(0.05, 20)
    return f


def make_flow(rng: random.Random, profile: str) -> tuple[Flow, int]:
    """Return (flow, src_unique_dports)."""
    c = f"10.0.{rng.randint(0, 5)}.{rng.randint(2, 250)}"
    s = f"{rng.randint(11, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    t0 = rng.uniform(0, 3600)
    g = lambda mu, sd, lo=40, hi=1514: int(min(hi, max(lo, rng.gauss(mu, sd))))
    if profile == "web":
        n = rng.randint(1, 12)
        starts = [t0 + sum(rng.expovariate(1 / rng.uniform(2, 90)) for _ in range(i)) for i in range(n)]
        k = rng.randint(8, 200)
        return _flow(rng, c, s, rng.choice([443, 443, 443, 80]), "tcp", starts, [g(180, 150) for _ in range(k)], [g(1100, 450) for _ in range(int(k * rng.uniform(1.2, 4)))]), rng.randint(1, 2)
    if profile == "custom_app":  # legitimate services on registered, non-standard ports (push, VPN, games, internal apps)
        n = rng.randint(1, 6)
        starts = [t0 + sum(rng.expovariate(1 / rng.uniform(20, 400)) for _ in range(i)) for i in range(n)]
        k = rng.randint(20, 600)
        return _flow(rng, c, s, rng.choice([5228, 8883, 1194, 5222, 3478, 27015, 8000, 9443, 51820]), rng.choice(["tcp", "tcp", "udp"]), starts, [g(220, 160) for _ in range(k)], [g(600, 450) for _ in range(int(k * rng.uniform(0.8, 3)))]), 1
    if profile == "video":
        k = rng.randint(400, 3000)
        return _flow(rng, c, s, 443, "tcp", [t0, t0 + rng.uniform(1, 30)], [g(80, 30) for _ in range(k // 3)], [g(1400, 120) for _ in range(k)]), 1
    if profile == "dns":
        n = rng.randint(1, 40)
        starts = [t0 + sum(rng.expovariate(1 / rng.uniform(1, 60)) for _ in range(i)) for i in range(n)]
        return _flow(rng, c, "10.0.0.53", 53, "udp", starts, [g(78, 10, 60, 120) for _ in range(n)], [g(130, 40, 70, 512) for _ in range(n)]), 1
    if profile == "ntp":
        n = rng.randint(3, 30)
        iv = rng.choice([64, 128, 256, 1024])
        starts = [t0 + i * iv + rng.uniform(-0.5, 0.5) for i in range(n)]
        return _flow(rng, c, s, 123, "udp", starts, [90] * n, [90] * n), 1
    if profile == "mail":
        n = rng.randint(2, 20)
        iv = rng.uniform(120, 900)
        starts = [t0 + i * iv * rng.uniform(0.7, 1.3) for i in range(n)]
        k = n * rng.randint(6, 30)
        return _flow(rng, c, s, rng.choice([993, 587, 465]), "tcp", starts, [g(200, 120) for _ in range(k)], [g(700, 400) for _ in range(k)]), 1
    if profile == "ssh_admin":
        k = rng.randint(100, 2500)
        return _flow(rng, c, f"10.0.{rng.randint(0, 5)}.{rng.randint(2, 250)}", 22, "tcp", [t0], [g(110, 40) for _ in range(k)], [g(160, 90) for _ in range(k)]), rng.randint(1, 2)
    if profile == "update_poll":  # legitimate periodic software (a realistic confounder for beaconing)
        n = rng.randint(4, 14)
        iv = rng.uniform(600, 3600)
        starts = [t0 + i * iv * rng.uniform(0.85, 1.15) for i in range(n)]
        k = n * rng.randint(8, 20)
        return _flow(rng, c, s, 443, "tcp", starts, [g(250, 100) for _ in range(k)], [g(900, 400) for _ in range(k)]), 1
    # ---- anomalies ----
    if profile == "beacon":
        n = rng.randint(12, 120)
        iv = rng.uniform(5, 300)
        jitter = rng.uniform(0, 0.08)
        starts = [t0 + i * iv * (1 + rng.uniform(-jitter, jitter)) for i in range(n)]
        port = rng.choice([4444, 8081, 9001, 1337, 53413, 6667, 8888, 443, 2222])
        return _flow(rng, c, s, port, "tcp", starts, [g(120, 15) for _ in range(n * 3)], [g(100, 15) for _ in range(n * 2)]), 1
    if profile == "exfil":
        k = rng.randint(4000, 30000)
        return _flow(rng, c, s, rng.choice([443, 21, 8443, 22, 9999]), "tcp", [t0, t0 + 1], [g(1450, 60) for _ in range(k)], [g(60, 6, 54, 80) for _ in range(k // rng.randint(8, 30))]), 1
    if profile == "scan_probe":
        return _flow(rng, c, f"10.0.{rng.randint(0, 5)}.{rng.randint(2, 250)}", rng.randint(1, 65535), "tcp", [t0], [60], [60] if rng.random() < 0.3 else []), rng.randint(40, 1000)
    if profile == "odd_port_interactive":
        k = rng.randint(200, 3000)
        return _flow(rng, c, s, rng.choice([4444, 31337, 5555, 12345, 50050, 61234]), "tcp", [t0], [g(90, 40) for _ in range(k)], [g(400, 350) for _ in range(k)]), 1
    raise ValueError(profile)
