# ARGUS Attack Lab

A tiny attacker/target pair for feeding real, attack-shaped traffic into
ARGUS's network and log detectors — entirely on your own machine.

**Scope guarantee:** `common.py` resolves every target and refuses
anything that isn't loopback or a private (RFC1918/RFC4193) address.
There's no way to point this at a real host. This is a test bench for
ARGUS's own detection logic, not a general attack tool.

## 1. Start the target

```bash
cd backend/scripts/attack_lab
../../../.venv/bin/python target_server.py --log-dir ./lab_out
```

Binds only to `127.0.0.1`:

| Port | Service | Purpose |
|---|---|---|
| 2222 | fake SSH | logs real `Failed password` lines to `lab_out/auth.log` in standard syslog/sshd format |
| 3306 | fake MySQL | banner only, a thing for a port scan to find |
| 8080 | HTTP | trivial app |
| 9001 | beacon listener | accepts/logs check-ins |
| 9002 | exfil sink | accepts and discards an upload, logs byte count |

## 2. Run the agent against it

```bash
../../../.venv/bin/python network_agent.py all --target 127.0.0.1 --out ./lab_out --attempts 10
```

`--attempts` must be **≥ 8** — that's ARGUS's own brute-force threshold
(`BRUTE_FORCE_MIN_FAILURES` in `app/analysis/logs.py`); fewer failures
and nothing fires, which is correct, not a bug.

Modes (run individually or via `all`):

- **portscan** — connects to ~20+ ports in quick succession → `network.port_scan`
- **beacon** — N evenly-spaced check-ins to port 9001 → `network.suspicious_port` (9001 is a known Tor ORPort in ARGUS's table); the stricter `network.beaconing` check needs near-metronomic timing (coefficient of variation < 0.15) and real OS scheduling jitter can push it just over that line — raise `--beacon-count` if you want it to land reliably
- **bruteforce** — repeated fake-SSH logins; the target's own `auth.log` is the real evidence, not a reconstruction
- **exfil** — one large real upload to the exfil sink; shows up in the flow graph, but ARGUS's `network.large_outbound_transfer` check only fires for *external* destinations by design, so a loopback target won't trip it — that's an honest limitation of this lab, not a broken detector
- **dnstunnel** — crafts DNS queries with long, high-entropy subdomains under one parent; no resolver needs to be running, since ARGUS reads the capture, not a response

For portscan/beacon/exfil/dnstunnel, the agent performs the real
network action *and* writes a PCAP reconstructing exactly what it did
(same hosts, ports, byte counts, and wall-clock timestamps) — because
ARGUS's network analysis reads a capture file, not a live interface,
and building the capture this way avoids needing raw-socket/root
privileges. Bruteforce needs no reconstruction: the target's `auth.log`
is already real, parseable evidence.

## 3. Feed it to ARGUS

```bash
INV=$(curl -s -X POST http://localhost:8000/api/investigations \
  -H "Content-Type: application/json" -d '{"title":"attack lab run"}')
ID=$(echo "$INV" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

curl -s -X POST "http://localhost:8000/api/investigations/$ID/evidence/file" \
  -F "kind=pcap" -F "file=@lab_out/combined.pcap"
curl -s -X POST "http://localhost:8000/api/investigations/$ID/evidence/file" \
  -F "kind=auth_log" -F "file=@lab_out/auth.log"

curl -s -X POST "http://localhost:8000/api/investigations/$ID/start"
```

Or just drag both files into "New Investigation" in the UI.

## Verified output (one real `all` run, 10 bruteforce attempts)

```
network.dns_tunneling_pattern   high    12 long, high-entropy DNS subdomains under lab-tunnel.test
network.port_scan               medium  22 distinct ports contacted
network.suspicious_port         medium  traffic to port 9001 (Tor ORPort)
ml.network_anomaly              low     13 flows flagged
auth.password_spraying          high    16 failed logins across 7 accounts
→ verdict: suspicious (confidence 0.886)
```

## Safety notes

- Everything binds to `127.0.0.1` only; `target_server.py` never listens
  on `0.0.0.0`.
- `assert_lab_target()` in `common.py` is the single point every attack
  mode goes through before opening a socket — it rejects anything that
  isn't loopback or RFC1918/RFC4193.
- If you want to run this against a VM instead of localhost, that's
  fine as long as the VM has a private address (e.g. `192.168.x.x`) —
  the guard allows that. It will not allow a public IP.
