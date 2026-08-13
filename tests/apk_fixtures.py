"""Minimal APK-shaped archives for tests.

Before T0.10 the pipeline tests used `b"PK\\x03\\x04" + b"stub" * 64`, which passes a
magic-byte check but is not a valid zip. Real M1 correctly rejects it as a corrupt
archive — so the fixtures had to become real zips.

These are **not parseable APKs**: androguard rejects the placeholder manifest, which is
the degradation path (`partial=True` with the reason in `errors`) rather than a crash.
Anything needing a genuinely parseable APK wants `canary/` (T0.9), not this.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path


def minimal_apk_bytes(*, package_hint: str = "com.example.stub") -> bytes:
    """A structurally valid zip with an `AndroidManifest.xml` at its root."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        # A placeholder, not real AXML. androguard will refuse it, on purpose.
        archive.writestr("AndroidManifest.xml", f"<manifest package='{package_hint}'/>")
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 128)
        archive.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 64)
        archive.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
    return buffer.getvalue()


def write_minimal_apk(path: Path, *, package_hint: str = "com.example.stub") -> Path:
    path.write_bytes(minimal_apk_bytes(package_hint=package_hint))
    return path
