"""M1 — ingest. What the uploaded file *is*, before any analysis of what it does.

docs/PHASE_0_FOUNDATIONS.md T0.10.

**This module never executes anything.** It hashes, reads zip headers, and asks
androguard to parse a manifest. Parsing is not running: androguard reads DEX and
resources as data. Detonation happens only on the sealed GCE detonator (CLAUDE.md).
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from drishti.contracts.evidence import EvidenceType
from drishti.contracts.static_report import FileMeta, ThreatIntel
from drishti.ledger.store import LedgerStore
from drishti.logging import get_logger
from drishti.m1_ingest import guards, intel
from drishti.m1_ingest.guards import IngestRejectedError

log = get_logger(__name__)


@dataclass(frozen=True)
class ManifestFacts:
    """What androguard could read from the manifest. All optional by design.

    A typed record rather than a dict: every field flows straight into `FileMeta`, and
    `dict[str, object]` would erase the types at exactly the boundary that matters.
    """

    package: str | None = None
    app_label: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    errors: tuple[str, ...] = field(default_factory=tuple)

    def as_ledger_content(self) -> dict[str, object]:
        return {
            k: v
            for k, v in {
                "package": self.package,
                "app_label": self.app_label,
                "version_name": self.version_name,
                "version_code": self.version_code,
                "min_sdk": self.min_sdk,
                "target_sdk": self.target_sdk,
            }.items()
            if v is not None
        }


#: Cap on bytes extracted while unpacking a bundle, independent of the header-declared
#: sizes the guards checked. A bomb that lies in its central directory still cannot
#: write more than this.
_EXTRACT_BUDGET_BYTES = 512 * 1024 * 1024


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ingest(
    path: Path,
    ledger: LedgerStore,
    *,
    filename: str | None = None,
    known_bad_path: Path | None = None,
    feed: intel.ReputationFeed | None = None,
    allow_label_derived: bool = False,
    seen_hashes: set[str] | None = None,
) -> FileMeta:
    """Hash, validate, identify, and record one upload.

    Order matters and is deliberate:
      1. structural guards (size, magic, zip-bomb) — cheapest, and they run before any
         attacker-controlled bytes reach a real parser
      2. sha256, which is the identity everything downstream keys on
      3. split-APK reassembly, if this is a bundle
      4. androguard manifest parse
      5. dedupe
      6. threat intel
      7. ledger

    Raises `IngestRejectedError` for input we refuse. Everything else degrades: a manifest
    that will not parse yields a `partial` FileMeta with the reason in `errors`, because
    a sample whose manifest is deliberately malformed is *interesting*, not a 500.
    """
    path = Path(path)
    name = filename or path.name

    size = guards.check_size(path)
    guards.check_magic(path)
    uncompressed, ratio = guards.check_zip_bomb(path)
    digest = sha256_file(path)

    errors: list[str] = []
    split_names: tuple[str, ...] = ()
    is_split = False
    base_path = path

    with TemporaryDirectory(prefix="drishti-bundle-") as tmp:
        if guards.is_apk_bundle(path):
            is_split = True
            try:
                base_path, split_names = _unpack_bundle(path, Path(tmp))
            except IngestRejectedError:
                raise
            except Exception as exc:
                errors.append(f"split-APK reassembly failed: {type(exc).__name__}: {exc}")
                base_path = path

        manifest = _parse_manifest(base_path)
        errors.extend(manifest.errors)

    dedupe_hit = bool(seen_hashes and digest in seen_hashes)

    known_bad = intel.load_known_bad(known_bad_path) if known_bad_path else {}
    reputation = intel.lookup(
        digest,
        known_bad=known_bad,
        feed=feed,
        allow_label_derived=allow_label_derived,
    )
    errors.extend(reputation.errors)

    refs = _write_ledger(
        ledger,
        digest=digest,
        name=name,
        size=size,
        uncompressed=uncompressed,
        ratio=ratio,
        manifest=manifest,
        is_split=is_split,
        split_names=split_names,
        reputation=reputation,
    )

    log.info(
        "ingested",
        sha256=digest,
        package=manifest.package,
        size_bytes=size,
        is_split=is_split,
        dedupe_hit=dedupe_hit,
        intel_verdict=reputation.verdict,
    )

    return FileMeta(
        sha256=digest,
        size_bytes=size,
        filename=name,
        package=manifest.package,
        app_label=manifest.app_label,
        version_name=manifest.version_name,
        version_code=manifest.version_code,
        min_sdk=manifest.min_sdk,
        target_sdk=manifest.target_sdk,
        is_split=is_split,
        split_names=split_names,
        dedupe_hit=dedupe_hit,
        intel=reputation,
        partial=bool(errors),
        errors=tuple(errors),
        ledger_refs=refs,
    )


def _unpack_bundle(path: Path, dest: Path) -> tuple[Path, tuple[str, ...]]:
    """Extract a `.apks`/`.xapk` and identify the base APK.

    The base is the member whose manifest has no `split` attribute. Naming conventions
    (`base.apk`, `split_config.*`) are a hint, not the rule — tools disagree, and a
    sample can name its files anything it likes.
    """
    extracted: list[Path] = []
    budget = _EXTRACT_BUDGET_BYTES
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if not info.filename.lower().endswith(".apk"):
                continue
            budget -= info.file_size
            if budget < 0:
                raise IngestRejectedError("bundle exceeds the extraction budget", code="zip_bomb")
            # Flatten the name: a member path like `../../etc/passwd.apk` must not
            # escape the temp directory (zip-slip).
            target = dest / Path(info.filename).name
            with archive.open(info) as src, target.open("wb") as out:
                out.write(src.read())
            extracted.append(target)

    if not extracted:
        raise IngestRejectedError("bundle contains no .apk members", code="empty_bundle")

    bases = [p for p in extracted if not _is_split_apk(p)]
    base = bases[0] if bases else extracted[0]
    splits = tuple(sorted(p.name for p in extracted if p != base))
    return base, splits


def _is_split_apk(path: Path) -> bool:
    """True if this APK declares a `split` attribute in its manifest."""
    try:
        from androguard.core.apk import APK

        apk = APK(str(path))
        return bool(apk.get_android_manifest_xml().get("split"))
    except Exception:
        return True


def _parse_manifest(path: Path) -> ManifestFacts:
    """androguard manifest facts, or a reason it could not be read.

    Wrapped broadly on purpose. androguard raises a wide variety of exceptions on
    hostile input, and a sample with a deliberately malformed manifest is a finding
    about the sample — not an error in the pipeline (00_GUIDING_MAP.md §9.2).
    """
    if not guards.looks_like_apk(path):
        return ManifestFacts(errors=("no AndroidManifest.xml at the archive root; not an APK",))
    try:
        from androguard.core.apk import APK

        apk = APK(str(path))
        raw_code = apk.get_androidversion_code()
        return ManifestFacts(
            package=apk.get_package() or None,
            app_label=apk.get_app_name() or None,
            version_name=apk.get_androidversion_name() or None,
            version_code=int(raw_code) if raw_code else None,
            min_sdk=int(apk.get_min_sdk_version() or 0) or None,
            target_sdk=int(apk.get_target_sdk_version() or 0) or None,
        )
    except Exception as exc:
        return ManifestFacts(errors=(f"manifest parse failed: {type(exc).__name__}: {exc}",))


def _write_ledger(
    ledger: LedgerStore,
    *,
    digest: str,
    name: str,
    size: int,
    uncompressed: int,
    ratio: float,
    manifest: ManifestFacts,
    is_split: bool,
    split_names: tuple[str, ...],
    reputation: ThreatIntel,
) -> tuple[str, ...]:
    """FILE_META, optional SPLIT_APK, and always a THREAT_INTEL node.

    Intel is recorded even when nothing is known: "no feed had an opinion on this file"
    is a finding, and `gamma` in the scorer reads whether intel exists at all.
    """
    refs: list[str] = []

    file_node = ledger.append(
        type=EvidenceType.FILE_META,
        source_tool="m1_ingest",
        content={
            "sha256": digest,
            "filename": name,
            "size_bytes": size,
            "uncompressed_bytes": uncompressed,
            "compression_ratio": round(ratio, 2),
            **manifest.as_ledger_content(),
        },
        location=name,
        confidence=1.0,
    )
    refs.append(file_node.id)

    if is_split:
        refs.append(
            ledger.append(
                type=EvidenceType.SPLIT_APK,
                source_tool="m1_ingest",
                content={"base_sha256": digest, "splits": list(split_names)},
                parents=(file_node.id,),
                confidence=1.0,
            ).id
        )

    refs.append(
        ledger.append(
            type=EvidenceType.THREAT_INTEL,
            source_tool=f"m1_ingest:{reputation.source}",
            content={
                "sha256": digest,
                "known_bad_hash": reputation.known_bad_hash,
                "detections": reputation.detections,
                "verdict": reputation.verdict,
                "family": reputation.family,
                "source": reputation.source,
                "label_derived": reputation.label_derived,
            },
            parents=(file_node.id,),
            # An affirmative match is certain; "nobody knows this file" is weak
            # evidence and must not be recorded as though it were strong.
            confidence=1.0
            if reputation.detections is not None or reputation.known_bad_hash
            else 0.3,
        ).id
    )
    return tuple(refs)
