"""
A deliberately vulnerable-looking local target for the attack_lab agent
to attack. Binds ONLY to 127.0.0.1 (never 0.0.0.0) so it is reachable
from this machine alone. Run this first, then point network_agent.py
at it.

Services:
  22   fake-SSH banner; any login attempt is logged to a real
       syslog-formatted auth.log (same format app/analysis/logs.py
       parses), so a brute-force run here produces genuine evidence.
  80   trivial HTTP "app" (a couple of real routes, everything else 404)
  3306 fake MySQL banner (just enough for a port scan to call it open)
  9001 beacon listener — accepts a connection, logs it, closes
  9002 exfil sink — accepts a connection, reads and discards bytes, logs size

Usage:
    python target_server.py --log-dir ./lab_out
"""
from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "127.0.0.1"


def syslog_line(host: str, msg: str) -> str:
    now = dt.datetime.now().strftime("%b %d %H:%M:%S")
    return f"{now} {host} sshd[{1000 + int(time.time()) % 9000}]: {msg}\n"


class AuthLog:
    def __init__(self, path: pathlib.Path):
        self.path = path
        self._lock = threading.Lock()
        self.path.touch(exist_ok=True)

    def write(self, msg: str) -> None:
        with self._lock, self.path.open("a") as fh:
            fh.write(syslog_line("lab-target", msg))


class FakeSSHHandler(socketserver.BaseRequestHandler):
    auth_log: AuthLog = None  # set by server factory

    def handle(self):
        try:
            self.request.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")
            data = self.request.recv(256)
            user = (data.decode(errors="ignore").strip() or "root")[:32]
            self.auth_log.write(
                f"Failed password for {user} from {self.client_address[0]} port "
                f"{self.client_address[1]} ssh2"
            )
            self.request.sendall(b"Permission denied, please try again.\r\n")
        except OSError:
            pass


class FakeMySQLHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(b"\x4a\x00\x00\x00\x0a5.7.0-fake\x00")
        except OSError:
            pass


class BeaconHandler(socketserver.BaseRequestHandler):
    log: AuthLog = None

    def handle(self):
        try:
            self.request.recv(64)
        except OSError:
            pass
        print(f"[beacon-listener] check-in from {self.client_address}")


class ExfilHandler(socketserver.BaseRequestHandler):
    def handle(self):
        total = 0
        try:
            while True:
                chunk = self.request.recv(65536)
                if not chunk:
                    break
                total += len(chunk)
        except OSError:
            pass
        print(f"[exfil-sink] received {total} bytes from {self.client_address}")


class HTTPHandler(BaseHTTPRequestHandler):
    def _respond(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/health"):
            self._respond(200, b"lab-target ok")
        else:
            self._respond(404, b"not found")

    def log_message(self, fmt, *args):  # quiet
        pass


class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_forever_in_thread(server) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--log-dir", default="./lab_out")
    args = ap.parse_args()

    log_dir = pathlib.Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    auth_log = AuthLog(log_dir / "auth.log")

    FakeSSHHandler.auth_log = auth_log

    servers = []
    ssh = ThreadingTCPServer((HOST, 2222), FakeSSHHandler)
    servers.append(("fake-ssh", 2222, ssh))
    mysql = ThreadingTCPServer((HOST, 3306), FakeMySQLHandler)
    servers.append(("fake-mysql", 3306, mysql))
    beacon = ThreadingTCPServer((HOST, 9001), BeaconHandler)
    servers.append(("beacon-listener", 9001, beacon))
    exfil = ThreadingTCPServer((HOST, 9002), ExfilHandler)
    servers.append(("exfil-sink", 9002, exfil))
    http = HTTPServer((HOST, 8080), HTTPHandler)
    servers.append(("http", 8080, http))

    print(f"[attack_lab] target listening on {HOST} only — not reachable off this box")
    for name, port, _ in servers:
        print(f"  {name:16s} {HOST}:{port}")
    print(f"[attack_lab] auth.log -> {auth_log.path}")

    threads = [serve_forever_in_thread(s) for _, _, s in servers]
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[attack_lab] shutting down")


if __name__ == "__main__":
    main()
