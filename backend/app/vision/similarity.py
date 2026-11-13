"""Screenshot similarity analysis (OpenCV).

What this measures: how visually close an uploaded screenshot is to a set of reference screenshots of
known legitimate pages, using four independent signals:
  * pHash  - 64-bit DCT perceptual hash (global structure, robust to scaling/compression)
  * dHash  - 64-bit gradient hash (layout edges)
  * colour - HSV histogram correlation (palette)
  * ORB    - local keypoint matches with a ratio test (logos, buttons, text blocks)
What it does NOT do: identify a brand, read text, or prove impersonation. A high score means "looks like
reference X". Whether that is impersonation depends on where the page was served from, which is decided
later by the correlation engine using URL evidence.
"""
import io
import json
from functools import lru_cache
from pathlib import Path

import cv2
import numpy as np
from PIL import Image

from ..config import get_settings

MATCH_THRESHOLD = 0.72


def decode(data: bytes) -> np.ndarray | None:
    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None or img.shape[0] < 16 or img.shape[1] < 16:
        return None
    if img.shape[0] * img.shape[1] > 40_000_000:
        return None
    return img


def phash(img: np.ndarray) -> int:
    g = cv2.resize(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY), (32, 32), interpolation=cv2.INTER_AREA).astype(np.float32)
    d = cv2.dct(g)[:8, :8]
    med = np.median(d.flatten()[1:])
    return int("".join("1" if v > med else "0" for v in d.flatten()), 2)


def dhash(img: np.ndarray) -> int:
    g = cv2.resize(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY), (9, 8), interpolation=cv2.INTER_AREA)
    return int("".join("1" if g[r, c] > g[r, c + 1] else "0" for r in range(8) for c in range(8)), 2)


def hamming_sim(a: int, b: int) -> float:
    return 1.0 - bin(a ^ b).count("1") / 64.0


def colour_sim(a: np.ndarray, b: np.ndarray) -> float:
    def hist(i):
        h = cv2.calcHist([cv2.cvtColor(cv2.resize(i, (256, 256)), cv2.COLOR_BGR2HSV)], [0, 1, 2], None, [12, 6, 6], [0, 180, 0, 256, 0, 256])
        return cv2.normalize(h, h).flatten()
    return float(max(0.0, cv2.compareHist(hist(a), hist(b), cv2.HISTCMP_CORREL)))


def _orb_desc(img: np.ndarray):
    g = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    scale = 800 / max(g.shape)
    if scale < 1:
        g = cv2.resize(g, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
    return cv2.ORB_create(nfeatures=600).detectAndCompute(g, None)


def orb_sim(a: np.ndarray, b: np.ndarray) -> tuple[float, int]:
    ka, da = _orb_desc(a)
    kb, db = _orb_desc(b)
    if da is None or db is None or len(ka) < 10 or len(kb) < 10:
        return 0.0, 0
    good = 0
    for pair in cv2.BFMatcher(cv2.NORM_HAMMING).knnMatch(da, db, k=2):
        if len(pair) == 2 and pair[0].distance < 0.75 * pair[1].distance:
            good += 1
    return min(1.0, good / max(1, min(len(ka), len(kb)) * 0.5)), good


def metadata(data: bytes) -> dict:
    try:
        im = Image.open(io.BytesIO(data))
        exif = {}
        try:
            for k, v in (im.getexif() or {}).items():
                if k in (271, 272, 305, 306, 36867):  # Make, Model, Software, DateTime, DateTimeOriginal
                    exif[{271: "make", 272: "model", 305: "software", 306: "datetime", 36867: "datetime_original"}[k]] = str(v)[:100]
        except Exception:
            pass
        text = {k: str(v)[:200] for k, v in (getattr(im, "text", {}) or {}).items()}
        return {"format": im.format, "width": im.width, "height": im.height, "mode": im.mode, "exif": exif, "text_chunks": text}
    except Exception as e:
        return {"error": f"metadata unreadable: {type(e).__name__}"}


@lru_cache
def load_references() -> list[dict]:
    """References live in data/references/: <name>.png plus references.json describing each page."""
    d = Path(get_settings().data_dir) / "references"
    index = d / "references.json"
    if not index.exists():
        return []
    refs = []
    for entry in json.loads(index.read_text()):
        p = d / entry["file"]
        img = decode(p.read_bytes()) if p.exists() else None
        if img is not None:
            refs.append({**entry, "img": img, "phash": phash(img), "dhash": dhash(img)})
    return refs


def compare(data: bytes) -> dict:
    img = decode(data)
    if img is None:
        return {"error": "image could not be decoded", "matches": []}
    ph, dh = phash(img), dhash(img)
    matches = []
    for ref in load_references():
        p, d = hamming_sim(ph, ref["phash"]), hamming_sim(dh, ref["dhash"])
        c = colour_sim(img, ref["img"])
        o, n_good = orb_sim(img, ref["img"])
        combined = 0.3 * p + 0.2 * d + 0.2 * c + 0.3 * o
        matches.append({"reference": ref["name"], "reference_file": ref["file"], "legitimate_domains": ref.get("legitimate_domains", []),
                        "phash_similarity": round(p, 3), "dhash_similarity": round(d, 3), "colour_similarity": round(c, 3), "orb_similarity": round(o, 3),
                        "orb_good_matches": n_good, "combined": round(combined, 3), "is_match": combined >= MATCH_THRESHOLD})
    matches.sort(key=lambda m: -m["combined"])
    return {"phash": f"{ph:016x}", "dhash": f"{dh:016x}", "reference_count": len(matches), "matches": matches[:5], "threshold": MATCH_THRESHOLD,
            "weights": {"phash": 0.3, "dhash": 0.2, "colour": 0.2, "orb": 0.3}}
