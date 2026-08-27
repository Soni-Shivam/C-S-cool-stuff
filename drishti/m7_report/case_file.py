"""The case file — every deliverable for one job in a single archive.

The Report tab already served each export on its own link. What it could not do is
answer the question an analyst actually asks six weeks later: *is this everything, and
was the evidence intact when it was taken?* Five files in a downloads folder cannot
answer that. One archive with a manifest can.

The manifest is the point of the format, not decoration. It states the sample hash,
the size and SHA-256 of every archived entry, the chain verification as it stood at
build time, and — the part that keeps this honest — **what was omitted and why**. An
export that failed is named in `omitted` with its reason rather than silently absent,
because a short archive and a complete one look identical from the outside.

Two things this module deliberately does not do:

- **It does not include the sample.** CLAUDE.md's hard boundary is that a real APK
  never leaves the analysis project, and a download button is not an exception. The
  archive is hashes and derived facts, which is exactly what the dossier already is.
- **It does not re-verify anything.** The chain state is passed in by the caller, which
  read it live. A module that re-verified here could report a different answer from the
  report inside the same archive.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

from drishti import __version__
from drishti.contracts.evidence import ChainVerification
from drishti.contracts.static_report import FileMeta

#: The manifest's name. Uppercase so it sorts first in every archive viewer.
MANIFEST_NAME = "MANIFEST.json"

#: Every entry a complete case file carries, in the order they are written. The route
#: builds exactly these; the contract test pins the set so an export cannot quietly
#: drop out of the bundle while its own single-file route keeps working.
CASE_FILE_NAMES: tuple[str, ...] = (
    "report.html",
    "complaint-package.json",
    "yara.yar",
    "stix.json",
    "ledger.json",
    "verdict.json",
)

#: A fixed DOS timestamp for every entry. Zip stores an mtime per member, so taking it
#: from the clock would make two archives of one unchanged job differ in bytes for no
#: reason a recipient could interpret. 1980-01-01 is the zip epoch.
_FIXED_MTIME = (1980, 1, 1, 0, 0, 0)

#: Stated inside every archive. Both sentences are properties of the system, not
#: reassurances: nothing here was submitted anywhere, and the sample is not present.
_NOTES: tuple[str, ...] = (
    "Nothing in this archive was filed, submitted or shared by DRISHTI. "
    "The complaint package is written for a person to attach to a complaint they raise "
    "themselves.",
    "The analysed sample is not included — this archive is hashes and derived facts only.",
    "Re-verify the evidence chain from ledger.json: it carries the ed25519 public key, "
    "the hash inputs and every signature.",
)


def _chain_state(chain: ChainVerification | None) -> dict[str, object]:
    """The chain as it was read at build time, or an explicit "not checked".

    A missing verification is recorded as such. Defaulting it to `verified: true`
    would make an unchecked archive indistinguishable from a verified one.
    """
    if chain is None:
        return {
            "verified": None,
            "reason": "the chain was not verified when this archive was built",
        }
    return {
        "verified": chain.ok,
        "node_count": chain.node_count,
        "first_bad_seq": chain.first_bad_seq,
        "reason": chain.reason,
    }


def build(
    *,
    job_id: str,
    meta: FileMeta,
    files: dict[str, bytes],
    chain: ChainVerification | None,
    generated_at: str,
    omitted: dict[str, str],
) -> bytes:
    """Assemble one job's deliverables into a zip archive, manifest first.

    `files` maps archive entry name to its exact bytes — the same bytes the single-file
    routes serve. `omitted` maps the name of an export that could not be produced to the
    reason, and both appear in the manifest.
    """
    contents = [
        {
            "name": name,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        for name, payload in files.items()
    ]
    manifest = {
        "drishti_version": __version__,
        "job_id": job_id,
        "sample_sha256": meta.sha256,
        "sample_filename": meta.filename,
        "sample_size_bytes": meta.size_bytes,
        "package": meta.package,
        "generated_at": generated_at,
        "contents": contents,
        "omitted": omitted,
        "evidence_chain": _chain_state(chain),
        "notes": list(_NOTES),
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        _write(archive, MANIFEST_NAME, json.dumps(manifest, indent=2, sort_keys=True).encode())
        for name, payload in files.items():
            _write(archive, name, payload)
    return buffer.getvalue()


def _write(archive: zipfile.ZipFile, name: str, payload: bytes) -> None:
    """One entry, with a pinned mtime so identical inputs give identical bytes."""
    info = zipfile.ZipInfo(filename=name, date_time=_FIXED_MTIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, payload)
