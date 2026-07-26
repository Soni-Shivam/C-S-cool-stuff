import hashlib
from pathlib import Path

from pydantic import BaseModel


class ApkBundle(BaseModel):
    path: str
    sha256: str
    size_bytes: int
    is_split: bool = False
    intel_hit: bool = False
    intel_family: str | None = None


def sha256_file(path: str | Path, chunk_size: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def load_known_bad(path: str | Path) -> dict[str, str]:
    feed: dict[str, str] = {}
    p = Path(path)
    if not p.exists():
        return feed
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "," not in line:
            continue
        sha, family = line.split(",", 1)
        feed[sha.strip().lower()] = family.strip()
    return feed


def ingest(apk_path, led, timestamp: str, known_bad: dict[str, str] | None = None) -> ApkBundle:
    p = Path(apk_path)
    sha = sha256_file(p)
    size = p.stat().st_size
    family = (known_bad or {}).get(sha.lower())
    intel_hit = family is not None

    led.append(
        "ingest",
        "drishti.ingestion",
        f"APK ingested: {p.name} ({size} bytes)",
        location=str(p),
        confidence=1.0,
        timestamp=timestamp,
    )
    if intel_hit:
        led.append(
            "intel",
            "threat_intel",
            f"SHA-256 matches known-bad family: {family}",
            location=sha,
            confidence=1.0,
            timestamp=timestamp,
        )
    return ApkBundle(
        path=str(p), sha256=sha, size_bytes=size,
        is_split=False, intel_hit=intel_hit, intel_family=family,
    )
