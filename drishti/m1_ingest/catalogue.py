"""The staged-sample catalogue: what is on the VM, and how to name one.

Uploading a file to demonstrate the system means the demonstration is only as good
as whatever the operator happened to have to hand. The catalogue is the alternative:
a small set of samples staged on the analysis VM whose nature is already known, so a
verdict can be put next to the truth and be seen to be right or wrong.

Everything here is deliberately small, because the interesting part is what it
refuses to do:

**It never yields bytes.** `load()` returns metadata; `resolve()` returns a path for
the *server* to open. No route exposes either the path or the content — the browser
names an id and the VM does the reading. A real sample does not leave the analysis
project (CLAUDE.md), and a picker in a dashboard is not an exception to that.

**It never joins user input into a path.** An id is matched against the ids the
manifest declares. `../../etc/passwd` is not one of them, so it resolves to nothing.
The filename is taken from the manifest entry and its own basename, so a manifest
naming `../x` still cannot escape either.

**It carries ground truth but never hands it to the analysis.** `label` and
`vt_detection` reach the API and the dashboard. They do not reach `submit()`, the
pipeline, the scorer, or a prompt — the caller passes a path and a filename, exactly
as the upload route does. This is not a convention: `m5_ml/reputation.py` refuses a
label-derived feed by default so that composite-score metrics cannot be circular,
and a VT count silently entering the pipeline through the side door would undo that
without failing anything.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from drishti.config import Settings
from drishti.contracts.sample import SampleEntry
from drishti.logging import get_logger

log = get_logger(__name__)

#: The file that describes the staged samples, inside `settings.samples_dir`.
MANIFEST_NAME = "manifest.json"


@dataclass(frozen=True)
class ResolvedSample:
    """A catalogue entry and the file it names. Server-side only."""

    entry: SampleEntry
    path: Path


def _digest(path: Path) -> str:
    """SHA-256 of what is actually on disk.

    Read from the file rather than trusted from the manifest: a declared hash that
    disagrees with the bytes would let the catalogue name one sample and analyse
    another, which is the one inconsistency a ground-truth comparison cannot survive.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load(settings: Settings) -> list[SampleEntry]:
    """Every staged sample this deployment can actually run.

    An empty list is the honest answer for a machine with no samples staged — a
    laptop, or CI. It is never an error, because the picker is an affordance and not
    a dependency.
    """
    directory = settings.samples_dir
    if directory is None:
        return []

    manifest = Path(directory) / MANIFEST_NAME
    if not manifest.is_file():
        log.warning("sample_manifest_missing", path=str(manifest))
        return []

    try:
        rows = json.loads(manifest.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("sample_manifest_unreadable", path=str(manifest), error=str(exc))
        return []
    if not isinstance(rows, list):
        log.warning("sample_manifest_not_a_list", path=str(manifest))
        return []

    entries: list[SampleEntry] = []
    for row in rows:
        entry = _entry(Path(directory), row)
        if entry is not None:
            entries.append(entry)
    return entries


def _entry(directory: Path, row: object) -> SampleEntry | None:
    """One manifest row, or None with a reason logged.

    A row this cannot honour is dropped rather than raised: one malformed entry must
    not empty the picker, and a sample whose file is absent must not become a button
    that fails when pressed.
    """
    if not isinstance(row, dict):
        log.warning("sample_row_not_an_object")
        return None

    identifier = str(row.get("id", "")).strip()
    # `Path(...).name` strips any directory part a manifest tried to smuggle in, so a
    # hostile manifest is no more dangerous than a hostile request.
    filename = Path(str(row.get("filename", ""))).name
    if not identifier or not filename:
        log.warning("sample_row_incomplete", id=identifier or None)
        return None

    path = directory / filename
    if not path.is_file():
        log.warning("sample_file_missing", id=identifier, path=str(path))
        return None

    try:
        return SampleEntry(
            id=identifier,
            package=str(row.get("package") or "unknown"),
            filename=filename,
            sha256=_digest(path),
            size_bytes=path.stat().st_size,
            label=row.get("label"),
            vt_detection=row.get("vt_detection"),
            note=row.get("note"),
        )
    except (ValidationError, OSError) as exc:
        log.warning("sample_row_invalid", id=identifier, error=str(exc))
        return None


def resolve(settings: Settings, sample_id: str) -> ResolvedSample | None:
    """The staged file for an id, or None if this deployment does not offer it.

    Matching, never joining: the id is compared against what the manifest declares,
    so no request can name a file the catalogue did not already list.
    """
    directory = settings.samples_dir
    if directory is None:
        return None
    for entry in load(settings):
        if entry.id == sample_id:
            return ResolvedSample(entry=entry, path=Path(directory) / entry.filename)
    return None
