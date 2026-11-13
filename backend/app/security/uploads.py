"""Upload validation, content-type sniffing and tamper-evident storage of original evidence."""
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from ..config import get_settings


class UploadRejected(Exception):
    pass


PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")
IMAGE_MAGICS = {b"\x89PNG\r\n\x1a\n": "image/png", b"\xff\xd8\xff": "image/jpeg", b"RIFF": "image/webp", b"GIF8": "image/gif", b"BM": "image/bmp"}
AUTH_LINE = re.compile(rb"(sshd|sudo|su|pam_unix|systemd-logind)(\[\d+\])?:", re.I)
HEADER_LINE = re.compile(rb"^(received|from|to|subject|return-path|message-id|authentication-results|date|reply-to):", re.I | re.M)
KINDS = {"url", "eml", "email_headers", "json_events", "auth_log", "pcap", "file", "pdf", "screenshot"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_name(name: str) -> str:
    """Strip any path components and unusual characters. The name is metadata only; it is never used as a path."""
    base = re.split(r"[\\/]", name or "")[-1].replace("\x00", "")
    base = re.sub(r"[^A-Za-z0-9._ ()\-]", "_", base).strip(" .")
    return (base or "unnamed")[:200]


def sniff_kind(data: bytes, filename: str = "") -> tuple[str, str]:
    """Decide the evidence kind from content first, extension second. Returns (kind, mime)."""
    head = data[:4096]
    ext = Path(filename).suffix.lower()
    if head.startswith(PCAP_MAGICS):
        return "pcap", "application/vnd.tcpdump.pcap"
    for magic, mime in IMAGE_MAGICS.items():
        if head.startswith(magic) and (magic != b"RIFF" or head[8:12] == b"WEBP"):
            return "screenshot", mime
    if head.startswith(b"%PDF-"):
        return "pdf", "application/pdf"
    if head.startswith(b"MZ"):
        return "file", "application/x-dosexec"
    if head.startswith(b"\x7fELF"):
        return "file", "application/x-elf"
    if head.startswith(b"PK\x03\x04"):
        return "file", "application/zip"
    text = head.lstrip()
    if text[:1] in (b"{", b"["):
        try:
            sample = data.decode("utf-8", errors="strict")
            first = sample.strip().splitlines()[0] if sample.strip() else ""
            json.loads(sample) if text[:1] == b"[" or "\n" not in sample.strip() else json.loads(first)
            return "json_events", "application/json"
        except (ValueError, UnicodeDecodeError):
            pass
    if b"\x00" not in head:
        n_hdr = len(HEADER_LINE.findall(head))
        if n_hdr >= 3:
            has_body = b"\r\n\r\n" in data or b"\n\n" in data.strip()
            return ("eml" if (ext == ".eml" or has_body) and ext != ".txt" else "email_headers"), "message/rfc822"
        if len(AUTH_LINE.findall(head)) >= 1:
            return "auth_log", "text/plain"
        if ext in (".log",):
            return "auth_log", "text/plain"
        return "file", "text/plain"
    return "file", "application/octet-stream"


def validate_upload(data: bytes, filename: str, declared_kind: str | None) -> tuple[str, str, str]:
    """Returns (kind, mime, safe_filename). Raises UploadRejected on policy violations."""
    s = get_settings()
    if not data:
        raise UploadRejected("empty upload")
    if len(data) > s.max_upload_bytes:
        raise UploadRejected(f"file exceeds the {s.max_upload_bytes} byte limit")
    name = safe_name(filename)
    kind, mime = sniff_kind(data, name)
    if declared_kind and declared_kind != "auto":
        if declared_kind not in KINDS or declared_kind == "url":
            raise UploadRejected(f"unsupported evidence kind '{declared_kind}'")
        structured = {"pcap", "screenshot", "pdf", "json_events", "eml"}
        if declared_kind in structured and kind != declared_kind and not (declared_kind == "eml" and kind == "email_headers"):
            raise UploadRejected(f"content does not match declared kind '{declared_kind}' (detected '{kind}')")
        if declared_kind in ("auth_log", "email_headers", "file"):
            if declared_kind != "file" and b"\x00" in data[:4096]:
                raise UploadRejected(f"binary content cannot be ingested as '{declared_kind}'")
            kind = declared_kind
    return kind, mime, name


def store_original(investigation_id: str, evidence_id: str, data: bytes) -> Path:
    """Write the original bytes under a server-generated path and make them read-only."""
    root = get_settings().storage_dir.resolve()
    if not re.fullmatch(r"[A-Z]+-[0-9A-F]{12}", investigation_id) or not re.fullmatch(r"[A-Z]+-[0-9A-F]{12}", evidence_id):
        raise UploadRejected("invalid identifier")
    target = (root / investigation_id / f"{evidence_id}.bin").resolve()
    if root not in target.parents:
        raise UploadRejected("path traversal detected")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(target, stat.S_IRUSR)  # no execute bit, read-only
    return target


def read_original(path: str) -> bytes:
    root = get_settings().storage_dir.resolve()
    p = Path(path).resolve()
    if root not in p.parents:
        raise UploadRejected("path traversal detected")
    return p.read_bytes()
