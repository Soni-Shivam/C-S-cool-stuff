"""M1 ingest: guards, split reassembly, manifest parsing, intel, ledger.

docs/PHASE_0_FOUNDATIONS.md T0.10.

The guard tests are the ones that matter most. *"A malformed upload crashing the API at
H70 is an avoidable embarrassment"* — and every input here is attacker-controlled.
"""

from __future__ import annotations

import zipfile

import pytest

from drishti.contracts.evidence import EvidenceType
from drishti.ledger.store import LedgerStore
from drishti.m1_ingest import guards, intel
from drishti.m1_ingest.guards import IngestRejectedError
from drishti.m1_ingest.ingest import ingest, sha256_file

JOB = "job_ingest_test"


@pytest.fixture
def ledger(tmp_path):
    store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
    store.open(JOB)
    yield store
    store.close()


def _make_apk(path, *, manifest=b"<manifest/>", extra=None, split=False):
    """A minimal zip that passes the structural guards.

    Not a *parseable* APK — androguard will reject the fake manifest, which is exactly
    the degradation path worth testing.
    """
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        if split:
            z.writestr("split_config.arm64_v8a", b"x")
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return path


# ── guards ───────────────────────────────────────────────────────────────────
def test_empty_file_is_rejected(tmp_path) -> None:
    p = tmp_path / "empty.apk"
    p.write_bytes(b"")
    with pytest.raises(IngestRejectedError) as exc:
        guards.check_size(p)
    assert exc.value.code == "empty"


def test_oversized_file_is_rejected(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(guards, "MAX_SIZE_BYTES", 10)
    p = tmp_path / "big.apk"
    p.write_bytes(b"x" * 100)
    with pytest.raises(IngestRejectedError) as exc:
        guards.check_size(p)
    assert exc.value.code == "too_large"


def test_non_zip_is_rejected_by_magic(tmp_path) -> None:
    """An uploaded .apk that is really a PDF fails here, not inside a parser."""
    p = tmp_path / "fake.apk"
    p.write_bytes(b"%PDF-1.7 not an apk at all")
    with pytest.raises(IngestRejectedError) as exc:
        guards.check_magic(p)
    assert exc.value.code == "not_zip"


def test_zip_bomb_is_rejected_without_extraction(tmp_path) -> None:
    """Detected from the central directory — nothing is written to find out."""
    p = tmp_path / "bomb.apk"
    with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
        z.writestr("bomb", b"\x00" * (8 * 1024 * 1024))  # compresses ~1000:1
    with pytest.raises(IngestRejectedError) as exc:
        guards.check_zip_bomb(p)
    assert exc.value.code == "zip_bomb"


def test_corrupt_zip_is_rejected_cleanly(tmp_path) -> None:
    p = tmp_path / "corrupt.apk"
    p.write_bytes(b"PK\x03\x04" + b"\xff" * 200)
    with pytest.raises(IngestRejectedError) as exc:
        guards.check_zip_bomb(p)
    assert exc.value.code == "corrupt_zip"


def test_a_real_apk_passes_the_guards(tmp_path) -> None:
    p = _make_apk(tmp_path / "ok.apk")
    assert guards.check_size(p) > 0
    guards.check_magic(p)
    _uncompressed, ratio = guards.check_zip_bomb(p)
    assert ratio < guards.MAX_COMPRESSION_RATIO
    assert guards.looks_like_apk(p) is True


def test_zip_without_manifest_is_not_an_apk(tmp_path) -> None:
    p = tmp_path / "notapk.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", b"hello")
    assert guards.looks_like_apk(p) is False


# ── hashing ──────────────────────────────────────────────────────────────────
def test_sha256_matches_hashlib(tmp_path) -> None:
    import hashlib

    p = _make_apk(tmp_path / "h.apk")
    assert sha256_file(p) == hashlib.sha256(p.read_bytes()).hexdigest()


# ── the happy-ish path ───────────────────────────────────────────────────────
def test_ingest_records_file_meta_and_intel(tmp_path, ledger) -> None:
    p = _make_apk(tmp_path / "sample.apk")
    meta = ingest(p, ledger, filename="sample.apk")

    assert meta.sha256 == sha256_file(p)
    assert meta.size_bytes == p.stat().st_size
    assert meta.filename == "sample.apk"

    types = [n.type for n in ledger.query(job_id=JOB)]
    assert EvidenceType.FILE_META in types
    assert EvidenceType.THREAT_INTEL in types, "intel is recorded even when nothing is known"
    assert ledger.verify_chain(JOB).ok is True


def test_unparseable_manifest_degrades_rather_than_raising(tmp_path, ledger) -> None:
    """A deliberately malformed manifest is a finding about the sample, not a 500."""
    meta = ingest(_make_apk(tmp_path / "bad.apk", manifest=b"\x00\x01broken"), ledger)
    assert meta.partial is True
    assert any("manifest" in e for e in meta.errors)
    assert meta.sha256, "hashing must still succeed"
    assert ledger.verify_chain(JOB).ok is True


def test_ledger_refs_point_at_real_nodes(tmp_path, ledger) -> None:
    meta = ingest(_make_apk(tmp_path / "r.apk"), ledger)
    assert meta.ledger_refs
    for ref in meta.ledger_refs:
        assert ledger.get(ref) is not None


def test_dedupe_is_reported_not_enforced(tmp_path, ledger) -> None:
    """A repeat upload is flagged, not refused — the caller decides what to do."""
    p = _make_apk(tmp_path / "d.apk")
    digest = sha256_file(p)
    assert ingest(p, ledger, seen_hashes=set()).dedupe_hit is False
    assert ingest(p, ledger, seen_hashes={digest}).dedupe_hit is True


# ── split APK bundles ────────────────────────────────────────────────────────
def test_apk_bundle_is_detected_by_content_not_extension(tmp_path) -> None:
    inner = _make_apk(tmp_path / "base.apk")
    bundle = tmp_path / "app.zip"  # deliberately not .apks/.xapk
    with zipfile.ZipFile(bundle, "w") as z:
        z.write(inner, "base.apk")
        z.write(inner, "split_config.arm64_v8a.apk")
    assert guards.is_apk_bundle(bundle) is True
    assert guards.is_apk_bundle(inner) is False


def test_bundle_ingest_records_splits(tmp_path, ledger) -> None:
    inner = _make_apk(tmp_path / "base.apk")
    bundle = tmp_path / "app.apks"
    with zipfile.ZipFile(bundle, "w") as z:
        z.write(inner, "base.apk")
        z.write(inner, "split_config.en.apk")
    meta = ingest(bundle, ledger, filename="app.apks")
    assert meta.is_split is True
    assert meta.split_names
    types = [n.type for n in ledger.query(job_id=JOB)]
    assert EvidenceType.SPLIT_APK in types


def test_bundle_with_no_apk_members_is_rejected(tmp_path, ledger) -> None:
    bundle = tmp_path / "empty.apks"
    with zipfile.ZipFile(bundle, "w") as z:
        z.writestr("notes.txt", b"nothing here")
    # No AndroidManifest and no .apk members: not a bundle and not an APK, so it fails
    # the manifest check rather than the bundle check.
    meta = ingest(bundle, ledger)
    assert meta.partial is True
    assert any("not an APK" in e for e in meta.errors)


def test_zip_slip_member_names_are_flattened(tmp_path, ledger) -> None:
    """A member named `../../evil.apk` must not escape the extraction directory."""
    inner = _make_apk(tmp_path / "b.apk")
    bundle = tmp_path / "slip.apks"
    with zipfile.ZipFile(bundle, "w") as z:
        z.write(inner, "base.apk")
        z.write(inner, "../../../../tmp/drishti-zip-slip-escaped.apk")
    ingest(bundle, ledger)
    from pathlib import Path

    assert not Path("/tmp/drishti-zip-slip-escaped.apk").exists(), "zip-slip escaped!"


# ── threat intel ─────────────────────────────────────────────────────────────
def test_known_bad_list_sets_the_override_flag(tmp_path, ledger) -> None:
    p = _make_apk(tmp_path / "kb.apk")
    digest = sha256_file(p)
    listing = tmp_path / "known_bad.txt"
    listing.write_text(f"# comment\n{digest},Anatsa\n")

    meta = ingest(p, ledger, known_bad_path=listing)
    assert meta.intel is not None
    assert meta.intel.known_bad_hash is True
    assert meta.intel.family == "Anatsa"
    assert intel.r_term(meta.intel) == 1.0


@pytest.mark.parametrize(
    ("detections", "expected_r", "verdict"),
    [
        (40, 1.00, "confirmed_bad"),
        (12, 0.90, "confirmed_bad"),
        (6, 0.65, "suspected_bad"),
        (2, 0.35, "grey"),
        (0, 0.05, "unknown"),
    ],
)
def test_graded_bands(detections, expected_r, verdict) -> None:
    """The fix for v1's dead R term: a VT-39 trojan must not score like a VT-1 one."""
    r, got = intel.band_for(detections)
    assert (r, got) == (expected_r, verdict)


def test_unknown_never_maps_to_zero() -> None:
    """Absence of detections is absence of evidence — a zero-day must not be discounted."""
    assert intel.r_term(None) == intel.R_UNKNOWN > 0.0
    assert intel.R_UNKNOWN > 0.0


def test_label_derived_feed_is_refused_by_default(tmp_path, ledger) -> None:
    """Using it would make any precision/recall over the composite score circular."""

    class VTFeed:
        label_derived = True
        name = "androzoo_vt"

        def lookup(self, sha256: str) -> int | None:
            return 39

    meta = ingest(_make_apk(tmp_path / "ld.apk"), ledger, feed=VTFeed())
    assert meta.intel is not None
    assert meta.intel.detections is None, "the count must not be used"
    assert meta.intel.label_derived is True
    assert any("circular" in e for e in meta.intel.errors)
    assert intel.r_term(meta.intel) == intel.R_UNKNOWN


def test_label_derived_feed_is_used_when_explicitly_allowed(tmp_path, ledger) -> None:
    class VTFeed:
        label_derived = True
        name = "virustotal_live"

        def lookup(self, sha256: str) -> int | None:
            return 39

    meta = ingest(_make_apk(tmp_path / "ok.apk"), ledger, feed=VTFeed(), allow_label_derived=True)
    assert meta.intel is not None
    assert meta.intel.detections == 39
    assert intel.r_term(meta.intel) == 1.0


def test_a_clean_intel_result_does_not_lower_r(tmp_path, ledger) -> None:
    """R is a floor-raiser only. A clean VT result must never reduce a score."""

    class CleanFeed:
        label_derived = False
        name = "clean"

        def lookup(self, sha256: str) -> int | None:
            return 0

    meta = ingest(_make_apk(tmp_path / "c.apk"), ledger, feed=CleanFeed())
    assert meta.intel is not None
    assert meta.intel.verdict == "unknown"
    assert intel.r_term(meta.intel) == intel.R_UNKNOWN


def test_intel_node_confidence_reflects_how_much_is_known(tmp_path, ledger) -> None:
    """ "Nobody knows this file" must not be recorded as strong evidence."""
    ingest(_make_apk(tmp_path / "u.apk"), ledger)
    node = ledger.query(job_id=JOB, type=EvidenceType.THREAT_INTEL)[0]
    assert node.confidence == 0.3
