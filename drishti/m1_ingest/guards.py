"""Upload guards. Refuse hostile or nonsensical input before anything parses it.

docs/PHASE_0_FOUNDATIONS.md T0.10: *"A malformed upload crashing the API at H70 is an
avoidable embarrassment."*

Every guard here runs **before** androguard sees the file. androguard is a large
parser handling attacker-controlled input, so the cheap structural checks come first
and the expensive parse only runs on something that is at least shaped like an APK.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

#: Hard cap. `PHASE_0` T0.10 says reject > 300MB.
MAX_SIZE_BYTES = 300 * 1024 * 1024

#: A zip whose contents expand by more than this is treated as a bomb. Real APKs sit
#: well under 10x because their bulk is already-compressed PNG, DEX and resources; a
#: 42.zip-style archive is orders of magnitude above it.
MAX_COMPRESSION_RATIO = 100.0

#: Absolute ceiling on uncompressed size, so a ratio check cannot be gamed by a large
#: compressed input with a merely-plausible ratio.
MAX_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024

#: Local file header magic. APKs are zips.
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


class IngestRejectedError(Exception):
    """The upload is refused. Carries a reason safe to show a user."""

    def __init__(self, reason: str, *, code: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


def check_size(path: Path) -> int:
    size = path.stat().st_size
    if size == 0:
        raise IngestRejectedError("file is empty", code="empty")
    if size > MAX_SIZE_BYTES:
        raise IngestRejectedError(
            f"file is {size} bytes, over the {MAX_SIZE_BYTES} byte limit", code="too_large"
        )
    return size


def check_magic(path: Path) -> None:
    """Reject anything that is not a zip, by reading its first four bytes.

    Cheaper and more honest than trusting a filename: an uploaded `.apk` that is really
    a PDF should fail here, not three layers down inside a parser.
    """
    with path.open("rb") as handle:
        head = handle.read(4)
    if head not in _ZIP_MAGICS:
        raise IngestRejectedError(
            f"not a zip archive (magic {head!r}); an APK must be a zip", code="not_zip"
        )


def check_zip_bomb(path: Path) -> tuple[int, float]:
    """Refuse archives that expand implausibly. Returns (uncompressed_size, ratio).

    Reads only the central directory — the declared sizes — so nothing is extracted to
    find out. A bomb that lies in its headers still cannot be extracted past these
    limits later, because extraction is bounded separately.
    """
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            uncompressed = sum(info.file_size for info in infos)
            compressed = sum(info.compress_size for info in infos) or 1
    except zipfile.BadZipFile as exc:
        raise IngestRejectedError(f"corrupt zip archive: {exc}", code="corrupt_zip") from exc

    if uncompressed > MAX_UNCOMPRESSED_BYTES:
        raise IngestRejectedError(
            f"archive expands to {uncompressed} bytes, over the limit", code="zip_bomb"
        )
    ratio = uncompressed / compressed
    if ratio > MAX_COMPRESSION_RATIO:
        raise IngestRejectedError(
            f"archive compression ratio {ratio:.0f}:1 exceeds {MAX_COMPRESSION_RATIO:.0f}:1",
            code="zip_bomb",
        )
    return uncompressed, ratio


def looks_like_apk(path: Path) -> bool:
    """True if the archive contains an `AndroidManifest.xml` at its root."""
    try:
        with zipfile.ZipFile(path) as archive:
            return "AndroidManifest.xml" in archive.namelist()
    except zipfile.BadZipFile:
        return False


def zip_members(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as archive:
        return archive.namelist()


def is_apk_bundle(path: Path) -> bool:
    """True for a `.apks`/`.xapk`/zip-of-apks — an archive whose members are APKs.

    Checked by content rather than extension: the same bundle arrives as `.apks`,
    `.xapk`, or a plain `.zip` depending on which tool produced it.
    """
    try:
        members = zip_members(path)
    except zipfile.BadZipFile:
        return False
    return "AndroidManifest.xml" not in members and any(m.lower().endswith(".apk") for m in members)
