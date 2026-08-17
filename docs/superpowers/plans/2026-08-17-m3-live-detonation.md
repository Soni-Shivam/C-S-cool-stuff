# M3 Live Detonation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `LiveSandboxSource.run()` produce a real, captured `DynamicTrace` from a
sample detonated on the sealed GCE detonator, by porting v1's proven harness, adding the
signed-containment-manifest layer, and wiring live invocation over IAP.

**Architecture:** The sealed VM runs a ported `DynamicHarness` that emits only the
redacted `ObservationArtifact` wire contract. The app side (`LiveSandboxSource`) uploads
the sample, invokes the harness over IAP-SSH, pulls the artifact back through GCS, and
converts it to a `DynamicTrace` via a `trace_builder` that runs the existing normaliser +
evasion detector and computes a deterministic `detonated` rule. Everything except the
live VM run is unit-tested against mocked `adb`/`frida`/SSH.

**Tech Stack:** Python 3.11 (app) / 3.10 (VM image), pydantic v2, `cryptography`
(Ed25519), frida `<17`, mitmproxy, Packer, Terraform, `gcloud`.

## Global Constraints

- **Detonation runs ONLY on the sealed GCE detonator VM.** No sample is executed on the
  laptop or in CI. All laptop tests use mocked `adb`/`frida`/SSH. (CLAUDE.md)
- **Contracts first.** Cross-module types are pydantic models in `drishti/contracts/`.
  Never pass a raw dict across a module boundary.
- **Every external call degrades.** Return partial results with `errors` populated; a
  failing sub-analyser never raises past its boundary.
- **Containment is a gate, not a report.** `require_containment` raises; a failure aborts
  the batch and never downgrades to a warning.
- **Redaction is enforced twice** — in the Frida hook and again in the `ObservationEvent`
  validator, which refuses to construct on unredacted sensitive text.
- **`simulated` is unrepresentable** on the egress path (`Literal[False]`).
- **Live-vs-replay is read from the trace**, never a config flag: populate
  `emulator_image`, `vm_instance_id`, `harness_version`, `captured_at`,
  `containment_verified`.
- **A sample that emitted nothing is `inconclusive`, never benign.**
- **Manifest signing keys are RAW HEX** (`Ed25519PrivateKey.from_private_bytes(bytes.fromhex(...))`),
  matching `infra/gcp/runtime_prepare.sh` — NOT the PEM format the ledger uses.
- **Python style:** `ruff` formatted, type hints on public functions, `structlog` logging
  via `drishti.logging.get_logger`. `make test` (contract+unit) green before any GCP spend.
- **Region is `us-east1-c`** (buckets are US-EAST1); recorded deviation from CLAUDE.md's
  `asia-south1`.
- **`@pytest.mark.gcp` tests are excluded from CI** and need a live lab.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `drishti/m3_dynamic/containment.py` (modify) | add `ContainmentManifest`, `sign_manifest`, `load_and_verify_manifest` | 1 |
| `scripts/verify_containment.py` (create) | CLI: verify containment → sign → write manifest | 2 |
| `drishti/m3_dynamic/harness.py` (create) | ported `DynamicHarness`, `collect_frida`, `HarnessConfig` | 3 |
| `scripts/dynamic_analyze.py` (create) | thin CLI over the harness (flock, args, pilot auth) | 4 |
| `drishti/m3_dynamic/trace_builder.py` (create) | `ObservationArtifact` → `DynamicTrace` + `detonated` rule | 5 |
| `infra/gcp/fake_c2.py` (create) | mitmproxy sinkhole addon | 6 |
| `infra/gcp/packer/detonator.pkr.hcl` (modify), `.env` (modify) | repoint provisioner paths; set region | 7 |
| `drishti/m3_dynamic/trace_source.py` (modify) | real `LiveSandboxSource.run()` + `available()` | 8 |
| `drishti/m3_dynamic/emulator.py` (create) | `Emulator` class extracted from harness (post-live) | 15 |

Tasks 9–14 are live GCP operations (no new files). Tasks are ordered so each ends with an
independently testable deliverable.

---

### Task 1: Containment manifest signing

**Files:**
- Modify: `drishti/m3_dynamic/containment.py` (append; do not touch existing functions)
- Test: `tests/unit/test_containment_manifest.py`

**Interfaces:**
- Consumes: `ContainmentReport` (existing in this file), `drishti.contracts.base.DrishtiModel`.
- Produces:
  - `ContainmentManifest(DrishtiModel)` with fields: `instance_id: str`, `image_version: str`,
    `verified_at: str` (ISO8601 UTC), `contained: bool`, `probe_trustworthy: bool`,
    `forbidden: tuple[str, ...]`, `reason: str`, `signature: str` (hex).
  - `manifest_signing_payload(m: ContainmentManifest) -> str` — canonical JSON of every
    field except `signature`, `sort_keys=True`.
  - `sign_manifest(report, *, instance_id, image_version, private_key_hex, now=None) -> ContainmentManifest`
  - `load_and_verify_manifest(path, public_key_hex, *, max_age_s=900, now=None) -> ContainmentManifest`
    — raises `ContainmentError` on bad signature, staleness, or an uncontained report.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_containment_manifest.py
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drishti.m3_dynamic.containment import (
    ContainmentError,
    ContainmentReport,
    ProbeResult,
    load_and_verify_manifest,
    manifest_signing_payload,
    sign_manifest,
)


def _keypair() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes_raw().hex()
    pub = key.public_key().public_bytes_raw().hex()
    return priv, pub


def _good_report() -> ContainmentReport:
    return ContainmentReport(
        verified=True,
        probe_trustworthy=True,
        results=(ProbeResult("169.254.169.254", 80, False, 1),),
        failures=(),
        reason="probe distinguishes open from closed",
    )


NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=timezone.utc)


def test_sign_then_load_round_trips(tmp_path) -> None:
    priv, pub = _keypair()
    manifest = sign_manifest(
        _good_report(), instance_id="drishti-detonator",
        image_version="drishti-m3-tools-123", private_key_hex=priv, now=NOW,
    )
    path = tmp_path / "manifest.json"
    path.write_text(manifest.model_dump_json())
    loaded = load_and_verify_manifest(path, pub, now=NOW)
    assert loaded.instance_id == "drishti-detonator"
    assert loaded.contained is True


def test_tampered_body_is_rejected(tmp_path) -> None:
    priv, pub = _keypair()
    manifest = sign_manifest(
        _good_report(), instance_id="i", image_version="v",
        private_key_hex=priv, now=NOW,
    )
    doc = json.loads(manifest.model_dump_json())
    doc["instance_id"] = "attacker-controlled"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(ContainmentError, match="signature"):
        load_and_verify_manifest(path, pub, now=NOW)


def test_stale_manifest_fails_closed(tmp_path) -> None:
    priv, pub = _keypair()
    manifest = sign_manifest(
        _good_report(), instance_id="i", image_version="v",
        private_key_hex=priv, now=NOW,
    )
    path = tmp_path / "manifest.json"
    path.write_text(manifest.model_dump_json())
    later = NOW + timedelta(seconds=3600)
    with pytest.raises(ContainmentError, match="stale"):
        load_and_verify_manifest(path, pub, now=later, max_age_s=900)


def test_uncontained_report_cannot_be_signed_into_a_pass() -> None:
    priv, _ = _keypair()
    bad = ContainmentReport(verified=False, probe_trustworthy=True,
                            failures=("8.8.8.8:53 is REACHABLE",), reason="leak")
    with pytest.raises(ContainmentError, match="not contained"):
        sign_manifest(bad, instance_id="i", image_version="v",
                      private_key_hex=priv, now=NOW)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_containment_manifest.py -v`
Expected: FAIL with ImportError (`sign_manifest` not defined).

- [ ] **Step 3: Write minimal implementation**

Append to `drishti/m3_dynamic/containment.py`:

```python
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from drishti.contracts.base import DrishtiModel


class ContainmentManifest(DrishtiModel):
    """The signed attestation that a detonation ran inside verified containment.

    Signed with the VM's raw-hex Ed25519 key (matching runtime_prepare.sh, NOT the
    ledger's PEM key). The harness refuses to detonate unless this loads and verifies.
    """

    instance_id: str
    image_version: str
    verified_at: str
    contained: bool
    probe_trustworthy: bool
    forbidden: tuple[str, ...] = ()
    reason: str = ""
    signature: str = ""


def manifest_signing_payload(manifest: ContainmentManifest) -> str:
    """Canonical bytes covered by the signature: every field except `signature`."""
    body = manifest.model_dump()
    body.pop("signature", None)
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _digest_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sign_manifest(
    report: ContainmentReport,
    *,
    instance_id: str,
    image_version: str,
    private_key_hex: str,
    now: datetime | None = None,
) -> ContainmentManifest:
    """Sign a VERIFIED report into a manifest. Refuses to sign an uncontained report."""
    if not (report.verified and report.probe_trustworthy):
        raise ContainmentError(f"refusing to sign: report is not contained ({report.summary})")
    when = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
    unsigned = ContainmentManifest(
        instance_id=instance_id,
        image_version=image_version,
        verified_at=when,
        contained=True,
        probe_trustworthy=True,
        forbidden=tuple(f"{r.host}:{r.port}" for r in report.results),
        reason=report.reason,
        signature="",
    )
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    signature = key.sign(_digest_hex(manifest_signing_payload(unsigned)).encode("ascii")).hex()
    return unsigned.model_copy(update={"signature": signature})


def load_and_verify_manifest(
    path: Path | str,
    public_key_hex: str,
    *,
    max_age_s: int = 900,
    now: datetime | None = None,
) -> ContainmentManifest:
    """Load a manifest and fail closed on a bad signature, staleness, or non-containment."""
    manifest = ContainmentManifest.model_validate_json(Path(path).read_text())
    if not (manifest.contained and manifest.probe_trustworthy):
        raise ContainmentError("manifest attests it was NOT contained")
    pub: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    digest = _digest_hex(manifest_signing_payload(manifest))
    try:
        pub.verify(bytes.fromhex(manifest.signature), digest.encode("ascii"))
    except (InvalidSignature, ValueError) as exc:
        raise ContainmentError("manifest signature is invalid") from exc
    verified_at = datetime.fromisoformat(manifest.verified_at)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if (current - verified_at).total_seconds() > max_age_s:
        raise ContainmentError(f"manifest is stale (>{max_age_s}s old)")
    return manifest
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_containment_manifest.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add drishti/m3_dynamic/containment.py tests/unit/test_containment_manifest.py
git commit -m "feat(m3): signed containment manifest (sign + fail-closed verify)"
```

---

### Task 2: verify_containment.py CLI

**Files:**
- Create: `scripts/verify_containment.py`
- Test: `tests/unit/test_verify_containment_cli.py`

**Interfaces:**
- Consumes: `containment.verify`, `containment.sign_manifest`, `ProbeRunner`.
- Produces: `run_verification(serial, *, private_key_hex, instance_id, image_version, out_path, runner) -> int`
  — returns 0 and writes a signed manifest on success; returns 3 and writes nothing on failure.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verify_containment_cli.py
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "verify_containment", Path("scripts/verify_containment.py")
)
verify_containment = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_containment)


def _priv() -> str:
    return Ed25519PrivateKey.generate().private_bytes_raw().hex()


def _contained_runner(serial: str, command: str) -> str:
    # Negative control unreachable; positive-control listener reachable; all forbidden blocked.
    if "45999" in command:
        return "DRISHTI_RC=0"
    return "DRISHTI_RC=1"


def _leaky_runner(serial: str, command: str) -> str:
    if "8.8.8.8" in command or "45999" in command:
        return "DRISHTI_RC=0"
    return "DRISHTI_RC=1"


def test_writes_signed_manifest_when_contained(tmp_path) -> None:
    out = tmp_path / "manifest.json"
    rc = verify_containment.run_verification(
        "emulator-5554", private_key_hex=_priv(), instance_id="i",
        image_version="v", out_path=out, runner=_contained_runner,
    )
    assert rc == 0
    assert out.is_file()


def test_no_manifest_and_nonzero_when_leaking(tmp_path) -> None:
    out = tmp_path / "manifest.json"
    rc = verify_containment.run_verification(
        "emulator-5554", private_key_hex=_priv(), instance_id="i",
        image_version="v", out_path=out, runner=_leaky_runner,
    )
    assert rc == 3
    assert not out.exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_verify_containment_cli.py -v`
Expected: FAIL (file `scripts/verify_containment.py` does not exist).

- [ ] **Step 3: Write minimal implementation**

```python
#!/usr/bin/env python3
"""Verify containment on the detonator and emit a signed manifest. Fails closed.

Runs ON THE VM only (invoked by `make lab-verify` over IAP). Exit 0 + manifest means
contained; any non-zero exit means DO NOT DETONATE and no manifest is written.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drishti.m3_dynamic.containment import (  # noqa: E402
    ProbeRunner,
    run_adb,
    sign_manifest,
    verify,
)

DEFAULT_OUT = Path("/var/lib/drishti/containment-manifest.json")
DEFAULT_KEY = Path("/etc/drishti/containment-signing.key")


def run_verification(
    serial: str,
    *,
    private_key_hex: str,
    instance_id: str,
    image_version: str,
    out_path: Path,
    runner: ProbeRunner = run_adb,
) -> int:
    report = verify(serial, runner=runner)
    if not (report.verified and report.probe_trustworthy):
        print(f"CONTAINMENT FAILED: {report.summary}: {report.reason}", file=sys.stderr)
        return 3
    manifest = sign_manifest(
        report, instance_id=instance_id, image_version=image_version,
        private_key_hex=private_key_hex,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(manifest.model_dump_json(indent=2))
    print(f"CONTAINED: manifest written to {out_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default=os.environ.get("DRISHTI_EMULATOR_SERIAL", "emulator-5554"))
    parser.add_argument("--key", type=Path, default=DEFAULT_KEY)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--instance-id", default=os.environ.get("DRISHTI_INSTANCE_ID", "drishti-detonator"))
    parser.add_argument("--image-version", default=os.environ.get("DRISHTI_IMAGE_VERSION", "unknown"))
    args = parser.parse_args()
    private_key_hex = args.key.read_text().strip()
    return run_verification(
        args.serial, private_key_hex=private_key_hex, instance_id=args.instance_id,
        image_version=args.image_version, out_path=args.out,
    )


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_verify_containment_cli.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add scripts/verify_containment.py tests/unit/test_verify_containment_cli.py
git commit -m "feat(m3): verify_containment CLI writes a signed manifest, fails closed"
```

---

### Task 3: Port the detonation harness

**Files:**
- Create: `drishti/m3_dynamic/harness.py`
- Test: `tests/unit/test_m3_harness.py`

**Interfaces:**
- Consumes: `ObservationArtifact`, `ObservationEvent`, `HarnessMetadata`, `SnapshotLifecycle`,
  `FailureRecord` (from `drishti.contracts.dynamic_trace`); `load_and_verify_manifest`
  (Task 1); `redact_text` (from `drishti.m3_dynamic.redaction`).
- Produces: `HarnessConfig`, `DynamicHarness(config, *, command, sleep, collector)`,
  `DynamicHarness.run() -> tuple[ObservationArtifact, int]`, `collect_frida(...)`, `HarnessFailure`.

**Port source:** `v1-reference/backend/scripts/dynamic_analyze.py` lines 36–460 (the
`DynamicHarness` class, `collect_frida`, helpers). Copy verbatim EXCEPT the changes below.

**Import changes (v1 → v2):**
- Delete `from drishti.sandbox.observation import (...)`; add
  `from drishti.contracts.dynamic_trace import (FailureRecord, HarnessMetadata,
  ObservationArtifact, ObservationEvent, SnapshotLifecycle)`.
- Delete `from drishti.sandbox.containment import load_and_verify_manifest`; add
  `from drishti.m3_dynamic.containment import load_and_verify_manifest`.
- Delete `from drishti.sandbox.redaction import redact_text`; add
  `from drishti.m3_dynamic.redaction import redact_text`.
- `HOOKS = Path(__file__).with_name("frida_hooks.js")` →
  `HOOKS = Path(__file__).with_name("scripts") / "hooks.js"`.

**Contract-shape changes (v2 differs from v1):**
- v2 timestamp fields are `str`, not `datetime`. Everywhere the artifact is built, call
  `.isoformat()`: `started_at=started.isoformat()`, `finished_at=finished.isoformat()`,
  and in every `FailureRecord(..., occurred_at=utcnow().isoformat())`,
  `containment_verified_at=containment_verified_at.isoformat() if containment_verified_at else None`.
- v2 `ObservationArtifact` has **no `safe_for_ingestion` property.** Replace the return
  line `return artifact, 0 if artifact.safe_for_ingestion else 2` with:
  ```python
  clean = artifact.outcome in ("completed", "inconclusive") and (
      artifact.snapshot is None or artifact.snapshot.after_restore == "passed"
  )
  return artifact, 0 if clean else 2
  ```
- `load_and_verify_manifest` (Task 1) takes a **public-key hex string**, not a key path.
  Change `HarnessConfig.trusted_public_key: Path` handling in `run()`:
  ```python
  manifest = load_and_verify_manifest(
      self.config.manifest, self.config.trusted_public_key.read_text().strip()
  )
  ```
  and read `manifest.instance_id` for the diagnostic line (unchanged).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_m3_harness.py
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drishti.m3_dynamic.containment import ContainmentReport, ProbeResult, sign_manifest
from drishti.m3_dynamic.harness import DynamicHarness, HarnessConfig


def _write_manifest(tmp_path: Path) -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    priv, pub = key.private_bytes_raw().hex(), key.public_key().public_bytes_raw().hex()
    report = ContainmentReport(verified=True, probe_trustworthy=True,
                               results=(ProbeResult("8.8.8.8", 53, False, 1),), reason="ok")
    manifest = sign_manifest(report, instance_id="i", image_version="img-1",
                             private_key_hex=priv, now=datetime.now(timezone.utc))
    mpath = tmp_path / "manifest.json"
    mpath.write_text(manifest.model_dump_json())
    pubpath = tmp_path / "pub.hex"
    pubpath.write_text(pub)
    return mpath, pubpath


def _ok(*_a, **_k) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="Success\npackage: name='com.x'\n1", stderr="")


def _make_apk(tmp_path: Path) -> Path:
    apk = tmp_path / "s.apk"
    apk.write_bytes(b"PK\x03\x04fixture")
    return apk


def test_happy_path_yields_completed_artifact(tmp_path) -> None:
    mpath, pubpath = _write_manifest(tmp_path)
    apk = _make_apk(tmp_path)
    events = [{"type": "observation", "technique": "SMS control", "mitre": "T1582",
              "source_hook": "SmsManager.sendTextMessage", "detail": "sent",
              "redacted": True, "occurred_at": datetime.now(timezone.utc).isoformat()}]
    harness = DynamicHarness(
        HarnessConfig(apk=apk, output=tmp_path / "out.json", duration_s=1, snapshot="clean",
                      avd_name="drishti", emulator_serial="emulator-5554",
                      emulator_image="img-1", manifest=mpath, trusted_public_key=pubpath),
        command=_ok, sleep=lambda _s: None,
        collector=lambda pkg, dur, hooks: (events, []),
    )
    artifact, code = harness.run()
    assert artifact.outcome == "completed"
    assert code == 0
    assert artifact.observations[0].mitre == "T1582"
    assert artifact.simulated is False


def test_empty_observations_is_inconclusive(tmp_path) -> None:
    mpath, pubpath = _write_manifest(tmp_path)
    apk = _make_apk(tmp_path)
    harness = DynamicHarness(
        HarnessConfig(apk=apk, output=tmp_path / "out.json", duration_s=1, snapshot="clean",
                      avd_name="drishti", emulator_serial="emulator-5554",
                      emulator_image="img-1", manifest=mpath, trusted_public_key=pubpath),
        command=_ok, sleep=lambda _s: None, collector=lambda pkg, dur, hooks: ([], []),
    )
    artifact, _ = harness.run()
    assert artifact.outcome == "inconclusive"


def test_containment_failure_aborts(tmp_path) -> None:
    apk = _make_apk(tmp_path)
    missing = tmp_path / "nope.json"
    pub = tmp_path / "pub.hex"
    pub.write_text("00" * 32)
    harness = DynamicHarness(
        HarnessConfig(apk=apk, output=tmp_path / "out.json", duration_s=1, snapshot="clean",
                      avd_name="drishti", emulator_serial="emulator-5554",
                      emulator_image="img-1", manifest=missing, trusted_public_key=pub),
        command=_ok, sleep=lambda _s: None, collector=lambda pkg, dur, hooks: ([], []),
    )
    artifact, code = harness.run()
    assert artifact.outcome == "failed"
    assert any(f.code == "containment_failed" for f in artifact.failures)
    assert code == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_m3_harness.py -v`
Expected: FAIL (`drishti.m3_dynamic.harness` does not exist).

- [ ] **Step 3: Write minimal implementation**

Create `drishti/m3_dynamic/harness.py` by copying `v1-reference/backend/scripts/dynamic_analyze.py`
lines 36–460 (from `HARNESS_VERSION = ...` through the end of `collect_frida`), then apply
every import and contract-shape change listed in the task's **Import changes** and
**Contract-shape changes** blocks above. Do NOT copy `parse_args`/`main`/`PilotAuthorization`/
`require_pilot_authorization` — those belong to Task 4. Keep `HarnessConfig`, `HarnessFailure`,
`run_command`, `_stop_process`, `sha256_file`, `utcnow`, `DynamicHarness`, `collect_frida`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_m3_harness.py -v`
Expected: PASS (3 tests). Then `uv run ruff check drishti/m3_dynamic/harness.py` and
`uv run mypy drishti/m3_dynamic/harness.py` clean.

- [ ] **Step 5: Commit**

```bash
git add drishti/m3_dynamic/harness.py tests/unit/test_m3_harness.py
git commit -m "feat(m3): port the detonation harness to v2 contracts (T4.1/T4.2)"
```

---

### Task 4: dynamic_analyze.py CLI entrypoint

**Files:**
- Create: `scripts/dynamic_analyze.py`
- Test: `tests/unit/test_dynamic_analyze_cli.py`

**Interfaces:**
- Consumes: `DynamicHarness`, `HarnessConfig` (Task 3).
- Produces: `PilotAuthorization`, `require_pilot_authorization(...)`, `build_config(args) -> HarnessConfig`,
  `main() -> int`.

**Port source:** `v1-reference/backend/scripts/dynamic_analyze.py` lines 92–120 (`PilotAuthorization`,
`require_pilot_authorization`) and 463–519 (`parse_args`, `main`), verbatim except:
- Imports come from `drishti.m3_dynamic.harness` (not local definitions).
- `main()` constructs `HarnessConfig(..., trusted_public_key=args.containment_public_key)`
  where that arg now defaults to `Path("/etc/drishti/containment-signing.pub")`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_dynamic_analyze_cli.py
from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("dynamic_analyze", Path("scripts/dynamic_analyze.py"))
dynamic_analyze = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dynamic_analyze)


def test_pilot_authorization_rejects_sha_mismatch() -> None:
    now = datetime(2026, 8, 17, tzinfo=timezone.utc)
    auth = dynamic_analyze.PilotAuthorization(
        approval_id="a", sha256="a" * 64, reviewed_by="human", runtime_image="img",
        approved_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
        max_duration_s=120,
    )
    path = Path("/tmp/auth.json")
    path.write_text(auth.model_dump_json())
    with pytest.raises(ValueError, match="SHA-256"):
        dynamic_analyze.require_pilot_authorization(
            path, apk_sha256="b" * 64, runtime_image="img", duration_s=120, now=now,
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_dynamic_analyze_cli.py -v`
Expected: FAIL (file does not exist).

- [ ] **Step 3: Write minimal implementation**

Create `scripts/dynamic_analyze.py`: `#!/usr/bin/env python3` docstring, `sys.path.insert`
for the repo root (as in Task 2), import `DynamicHarness`/`HarnessConfig` from
`drishti.m3_dynamic.harness`, then paste the ported `PilotAuthorization`,
`require_pilot_authorization`, `parse_args`, and `main` per the port source above. End with
`if __name__ == "__main__": raise SystemExit(main())`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_dynamic_analyze_cli.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/dynamic_analyze.py tests/unit/test_dynamic_analyze_cli.py
git commit -m "feat(m3): dynamic_analyze CLI with the pilot-authorization gate"
```

---

### Task 5: ObservationArtifact → DynamicTrace bridge

**Files:**
- Create: `drishti/m3_dynamic/trace_builder.py`
- Test: `tests/unit/test_trace_builder.py`

**Interfaces:**
- Consumes: `ObservationArtifact` (contract), `normaliser.aggregate`, `evasion.detect`,
  `DynamicTrace`, `ApiEvent`, `EvasionObservation` (contract), `TraceSourceKind`, `new_id`.
- Produces:
  - `DETONATION_RULES: tuple[tuple[str, str], ...]` — (reason, predicate-key).
  - `compute_detonated(techniques, hooks) -> tuple[bool, str | None]`.
  - `artifact_to_trace(artifact, *, source, vm_instance_id=None) -> DynamicTrace`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_trace_builder.py
from __future__ import annotations

from datetime import datetime, timezone

from drishti.contracts.dynamic_trace import (
    HarnessMetadata,
    ObservationArtifact,
    ObservationEvent,
    TraceSourceKind,
)
from drishti.m3_dynamic.trace_builder import artifact_to_trace, compute_detonated


def _artifact(events: list[ObservationEvent], outcome: str = "completed") -> ObservationArtifact:
    now = datetime.now(timezone.utc).isoformat()
    return ObservationArtifact(
        sha256="a" * 64, package="com.x", outcome=outcome,
        observations=tuple(events),
        metadata=HarnessMetadata(harness_version="h1", hook_version="k1",
                                 emulator_image="img-1", emulator_serial="emulator-5554",
                                 avd_name="drishti"),
        started_at=now, finished_at=now,
    )


def _event(technique: str, mitre: str, hook: str) -> ObservationEvent:
    return ObservationEvent(technique=technique, mitre=mitre, source_hook=hook,
                            detail="", redacted=True,
                            occurred_at=datetime.now(timezone.utc).isoformat())


def test_dex_load_marks_detonated() -> None:
    detonated, reason = compute_detonated({"T1407"}, {"DexClassLoader.$init"})
    assert detonated is True
    assert reason == "runtime_dex_load"


def test_probe_only_is_not_detonated() -> None:
    detonated, reason = compute_detonated({"T1418"}, {"PackageManager.getPackageInfo"})
    assert detonated is False
    assert reason is None


def test_artifact_with_sms_forward_becomes_detonated_trace() -> None:
    art = _artifact([_event("SMS control", "T1582", "SmsManager.sendTextMessage")])
    trace = artifact_to_trace(art, source=TraceSourceKind.LIVE, vm_instance_id="vm-9")
    assert trace.source == TraceSourceKind.LIVE
    assert trace.detonated is True
    assert trace.detonation_reason == "sms_forwarded"
    assert trace.vm_instance_id == "vm-9"
    assert trace.emulator_image == "img-1"
    assert trace.synthetic is False


def test_empty_artifact_is_inconclusive_not_benign() -> None:
    art = _artifact([], outcome="inconclusive")
    trace = artifact_to_trace(art, source=TraceSourceKind.LIVE)
    assert trace.detonated is False
    assert trace.outcome == "inconclusive"
    assert len(trace.evasion_observations) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_trace_builder.py -v`
Expected: FAIL (module does not exist).

- [ ] **Step 3: Write minimal implementation**

```python
"""ObservationArtifact (VM wire contract) -> DynamicTrace (app contract).

docs/PHASE_4_DYNAMIC_SANDBOX.md T4.6. Runs app-side after the artifact is pulled back,
so the deterministic `detonated` rule and the normaliser/evasion passes are fully
unit-tested off the VM. The VM harness only ever emits the redacted ObservationArtifact.
"""
from __future__ import annotations

from drishti.contracts.dynamic_trace import (
    ApiEvent,
    DynamicTrace,
    ObservationArtifact,
    TraceSourceKind,
)
from drishti.contracts.dynamic_trace import EvasionObservation as EvasionContract
from drishti.logging import get_logger
from drishti.m3_dynamic import evasion, normaliser
from drishti.util import new_id

log = get_logger(__name__)

#: (detonation_reason, matcher). Each matcher gets (techniques, hooks) and returns bool.
#: The FIRST rule that fires names the reason. Written down once; see T4.6.
_RULES = (
    ("runtime_dex_load", lambda t, h: "T1407" in t),
    ("sms_forwarded", lambda t, h: any("sendTextMessage" in x for x in h) or "T1582" in t),
    ("overlay_added", lambda t, h: any("addView" in x for x in h) or "T1417" in t),
    ("command_exec", lambda t, h: any(x.split(".")[0] in ("Runtime", "ProcessBuilder") for x in h) or "T1623" in t),
)


def compute_detonated(techniques: set[str], hooks: set[str]) -> tuple[bool, str | None]:
    """Deterministic detonation verdict. True iff a §2.3 rule fired; names the first."""
    for reason, matches in _RULES:
        if matches(techniques, hooks):
            return True, reason
    return False, None


def artifact_to_trace(
    artifact: ObservationArtifact,
    *,
    source: TraceSourceKind,
    vm_instance_id: str | None = None,
) -> DynamicTrace:
    """Convert a detonator artifact into a schema-valid DynamicTrace."""
    events = [
        {"technique": o.technique, "mitre": o.mitre, "source_hook": o.source_hook, "detail": o.detail}
        for o in artifact.observations
    ]
    normalised = normaliser.aggregate(events)
    verdict = evasion.detect(normalised, installed_and_ran=artifact.package is not None)

    api_events = tuple(
        ApiEvent(t_ms=0, api=g.hook, args=(), retval=None, count=g.occurrences)
        for g in normalised.groups
    )
    evasion_observations = tuple(
        EvasionContract(
            probe_kind=obs.morph, queried=obs.detail, result="MISS", t_ms=0,
            followed_by_stall=verdict.stalled, inferred_requirement=obs.detail,
        )
        for obs in verdict.observations
    )

    hooks = {o.source_hook for o in artifact.observations}
    techniques = {o.mitre for o in artifact.observations}
    detonated, reason = compute_detonated(techniques, hooks)

    return DynamicTrace(
        run_id=new_id("run"),
        source=source,
        detonated=detonated,
        detonation_reason=reason,
        outcome=artifact.outcome,
        api_events=api_events,
        evasion_observations=evasion_observations,
        synthetic=False,
        emulator_image=artifact.metadata.emulator_image,
        vm_instance_id=vm_instance_id,
        harness_version=artifact.metadata.harness_version,
        containment_verified=artifact.metadata.containment_verified,
        captured_at=artifact.finished_at,
        errors=tuple(f.message for f in artifact.failures),
        partial=bool(artifact.failures),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_trace_builder.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add drishti/m3_dynamic/trace_builder.py tests/unit/test_trace_builder.py
git commit -m "feat(m3): artifact->trace bridge with the deterministic detonated rule (T4.6)"
```

---

### Task 6: fake_c2 sinkhole addon

**Files:**
- Create: `infra/gcp/fake_c2.py`
- Test: `tests/unit/test_fake_c2.py`

**Interfaces:**
- Produces: `TEMPLATES: dict[str, dict]`, `response_body(path: str) -> dict`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_fake_c2.py
from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location("fake_c2", Path("infra/gcp/fake_c2.py"))
fake_c2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fake_c2)


def test_known_path_returns_template() -> None:
    assert fake_c2.response_body("/config") == {"enabled": False, "commands": []}


def test_unknown_path_is_sinkholed() -> None:
    assert fake_c2.response_body("/anything") == {"status": "sinkholed", "commands": []}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_fake_c2.py -v`
Expected: FAIL (file does not exist).

- [ ] **Step 3: Write minimal implementation**

Port `v1-reference/infra/m3/fake_c2.py`, factoring the body lookup into a testable
function (the `request` hook must not need mitmproxy imported at test time):

```python
"""No-upstream mitmproxy sinkhole. Every request gets a deterministic local response.

The C2 stays dead (PHASE_4 safety control 6): outbound never reaches real attacker
infrastructure. Synthesised *adaptive* responses are P5's GenerativeC2; this is the
static floor that keeps a detonation contained.
"""
from __future__ import annotations

import json

TEMPLATES: dict[str, dict] = {
    "/fixture": {"status": "ok", "fixture": True},
    "/register": {"status": "registered", "next": "/fixture"},
    "/config": {"enabled": False, "commands": []},
}


def response_body(path: str) -> dict:
    return TEMPLATES.get(path, {"status": "sinkholed", "commands": []})


def request(flow) -> None:  # noqa: ANN001 - mitmproxy HTTPFlow, imported only on the VM
    from mitmproxy import http

    flow.response = http.Response.make(
        200,
        json.dumps(response_body(flow.request.path)).encode(),
        {"Content-Type": "application/json", "X-DRISHTI-No-Upstream": "true"},
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_fake_c2.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add infra/gcp/fake_c2.py tests/unit/test_fake_c2.py
git commit -m "feat(m3): fake_c2 sinkhole addon, testable off the VM"
```

---

### Task 7: Fix Packer provisioner paths and region

**Files:**
- Modify: `infra/gcp/packer/detonator.pkr.hcl:33-43`
- Modify: `.env` (set `DRISHTI_GCP_ZONE=us-east1-c`)
- Test: `tests/contract/test_infra_paths.py`

**Interfaces:** none (build config). The test asserts every `provisioner "file"` source in
the Packer template resolves to a real repo path.

- [ ] **Step 1: Write the failing test**

```python
# tests/contract/test_infra_paths.py
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKER = ROOT / "infra/gcp/packer/detonator.pkr.hcl"


def test_every_packer_file_source_exists() -> None:
    text = PACKER.read_text()
    sources = re.findall(r'provisioner "file"\s*\{\s*source\s*=\s*"([^"]+)"', text)
    packer_dir = PACKER.parent
    missing = []
    for src in sources:
        if "${var." in src:  # variable-driven APK paths are supplied at build time
            continue
        resolved = (packer_dir / src.replace("${path.root}", ".")).resolve()
        if not resolved.exists():
            missing.append(src)
    assert not missing, f"Packer references non-existent paths: {missing}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/contract/test_infra_paths.py -v`
Expected: FAIL (v1 `backend/*` paths do not exist).

- [ ] **Step 3: Write minimal implementation**

Replace `detonator.pkr.hcl` lines 36–43 (the `backend/*` provisioners) with v2 paths:

```hcl
  provisioner "file" { source = "${path.root}/../../../drishti" destination = "/tmp/drishti" }
  provisioner "file" { source = "${path.root}/../../../drishti/m3_dynamic/scripts/hooks.js" destination = "/tmp/frida_hooks.js" }
  provisioner "file" { source = "${path.root}/../../../scripts/dynamic_analyze.py" destination = "/tmp/dynamic_analyze.py" }
  provisioner "file" { source = "${path.root}/../../../scripts/verify_containment.py" destination = "/tmp/verify_containment.py" }
  provisioner "file" { source = "${path.root}/../emulator_control.sh" destination = "/tmp/emulator_control.sh" }
  provisioner "file" { source = "${path.root}/../runtime_lockdown.sh" destination = "/tmp/runtime_lockdown.sh" }
  provisioner "file" { source = "${path.root}/../runtime_prepare.sh" destination = "/tmp/runtime_prepare.sh" }
  provisioner "file" { source = "${path.root}/../fake_c2.py" destination = "/tmp/fake_c2.py" }
```

Then in `.env`, set `DRISHTI_GCP_ZONE=us-east1-c` (replace the `asia-south1-a` line).
Note in `builder_setup.sh` the provisioned `/tmp/dynamic_analyze.py` imports the `drishti`
package — confirm `PYTHONPATH=/opt/drishti/harness` covers both `dynamic_analyze` and
`drishti/` (it copies `/tmp/drishti` → `/opt/drishti/harness/drishti`, so the package is
importable; the harness's `from drishti.m3_dynamic...` imports resolve).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/contract/test_infra_paths.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add infra/gcp/packer/detonator.pkr.hcl tests/contract/test_infra_paths.py .env.example
git commit -m "fix(m3): repoint Packer provisioners to v2 paths; region us-east1-c"
```
(Note: `.env` is gitignored — commit the change to `.env.example` instead and set `.env` locally.)

---

### Task 8: LiveSandboxSource.run() and available()

**Files:**
- Modify: `drishti/m3_dynamic/trace_source.py:90-116` (the `LiveSandboxSource` class)
- Test: `tests/unit/test_live_sandbox_source.py`

**Interfaces:**
- Consumes: `artifact_to_trace` (Task 5), `ObservationArtifact`, `SandboxPlan`, `DynamicTrace`.
- Produces: `LiveSandboxSource(*, project, zone, instance, corpus_bucket, artifacts_bucket,
  runner=None, gcs=None)`; a `DetonatorRunner` protocol `(argv: list[str]) -> str`. The
  runner is injected so tests never call `gcloud`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_live_sandbox_source.py
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from drishti.contracts.dynamic_trace import HarnessMetadata, ObservationArtifact, TraceSourceKind
from drishti.contracts.frontier import SandboxPlan
from drishti.m3_dynamic.trace_source import LiveSandboxSource


def _artifact_json() -> str:
    now = datetime.now(timezone.utc).isoformat()
    return ObservationArtifact(
        sha256="a" * 64, package="com.x", outcome="completed",
        metadata=HarnessMetadata(harness_version="h1", hook_version="k1",
                                 emulator_image="img-1", emulator_serial="emulator-5554",
                                 avd_name="drishti", containment_verified=True),
        started_at=now, finished_at=now,
    ).model_dump_json()


def test_run_returns_live_trace(tmp_path) -> None:
    apk = tmp_path / "s.apk"
    apk.write_bytes(b"PK\x03\x04")
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> str:
        calls.append(argv)
        return _artifact_json() if argv and argv[0] == "pull" else ""

    src = LiveSandboxSource(project="p", zone="z", instance="drishti-detonator",
                            corpus_bucket="b-corpus", artifacts_bucket="b-art", runner=runner)
    trace = src.run(apk, SandboxPlan())
    assert trace.source == TraceSourceKind.LIVE
    assert trace.outcome == "completed"
    assert trace.vm_instance_id == "drishti-detonator"
    assert any(c[0] == "push" for c in calls)  # sample uploaded before detonation


def test_available_false_when_vm_not_running() -> None:
    src = LiveSandboxSource(project="p", zone="z", instance="i",
                            corpus_bucket="b", artifacts_bucket="b",
                            runner=lambda argv: "TERMINATED")
    assert src.available() is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_live_sandbox_source.py -v`
Expected: FAIL (`LiveSandboxSource.__init__` signature differs; `run` raises).

- [ ] **Step 3: Write minimal implementation**

Replace the `LiveSandboxSource` class body. The `runner` abstracts the three real
operations (`push` sample→GCS, `detonate` over IAP-SSH, `pull` artifact←GCS); the default
runner shells out to `gcloud`/`gsutil`, and tests inject a fake.

```python
from collections.abc import Callable

from drishti.m3_dynamic.trace_builder import artifact_to_trace
from drishti.contracts.dynamic_trace import ObservationArtifact

#: (op, *args) -> stdout. op in {"status","push","detonate","pull"}. Injected in tests.
DetonatorRunner = Callable[[list[str]], str]


class LiveSandboxSource(TraceSource):
    """Real detonation on the sealed GCE detonator, driven over IAP.

    Never runs a sample locally. `run()` uploads the APK to the corpus bucket, invokes
    the harness on the VM over IAP-SSH, and pulls the ObservationArtifact back through
    the artifacts bucket. The VM is the only place a sample executes (CLAUDE.md).
    """

    def __init__(
        self,
        *,
        project: str | None = None,
        zone: str = "us-east1-c",
        instance: str = "drishti-detonator",
        corpus_bucket: str | None = None,
        artifacts_bucket: str | None = None,
        duration_s: int = 120,
        runner: DetonatorRunner | None = None,
    ) -> None:
        self._project = project
        self._zone = zone
        self._instance = instance
        self._corpus = corpus_bucket
        self._artifacts = artifacts_bucket
        self._duration = duration_s
        self._runner = runner or self._default_runner

    @property
    def kind(self) -> TraceSourceKind:
        return TraceSourceKind.LIVE

    def available(self) -> bool:
        if not (self._project and self._corpus and self._artifacts):
            return False
        try:
            return self._runner(["status"]).strip() == "RUNNING"
        except Exception as exc:  # noqa: BLE001 - unavailability is data, never a crash
            log.info("detonator_status_failed", error=str(exc))
            return False

    def run(self, apk_path: Path, plan: SandboxPlan) -> DynamicTrace:
        if not self.available():
            raise TraceSourceUnavailableError("detonator is not available")
        digest = _sha256_of(apk_path)
        self._runner(["push", str(apk_path), digest])
        self._runner(["detonate", digest, str(self._duration)])
        raw = self._runner(["pull", digest])
        if not raw.strip():
            raise TraceSourceUnavailableError("detonator returned no artifact")
        artifact = ObservationArtifact.model_validate_json(raw)
        return artifact_to_trace(artifact, source=TraceSourceKind.LIVE,
                                 vm_instance_id=self._instance)

    def _default_runner(self, argv: list[str]) -> str:
        import subprocess

        op, rest = argv[0], argv[1:]
        if op == "status":
            out = subprocess.run(
                ["gcloud", "compute", "instances", "describe", self._instance,
                 f"--zone={self._zone}", f"--project={self._project}",
                 "--format=value(status)"],
                capture_output=True, text=True, timeout=60, check=False)
            return out.stdout
        if op == "push":
            apk_path, digest = rest
            subprocess.run(
                ["gsutil", "cp", apk_path, f"gs://{self._corpus}/{digest}.apk"],
                capture_output=True, text=True, timeout=600, check=True)
            return ""
        if op == "detonate":
            digest, duration = rest
            cmd = (
                f"sudo /opt/drishti/venv/bin/python /opt/drishti/harness/dynamic_analyze.py "
                f"gs://{self._corpus}/{digest}.apk --out /opt/drishti/results/{digest}.json "
                f"--duration {duration} --emulator-image "
                f"$(cat /opt/drishti/tools/frida-version.txt) && "
                f"gsutil cp /opt/drishti/results/{digest}.json "
                f"gs://{self._artifacts}/{digest}.json")
            subprocess.run(
                ["gcloud", "compute", "ssh", self._instance, f"--zone={self._zone}",
                 f"--project={self._project}", "--tunnel-through-iap", "--command", cmd],
                capture_output=True, text=True, timeout=self._duration + 600, check=True)
            return ""
        if op == "pull":
            (digest,) = rest
            out = subprocess.run(
                ["gsutil", "cat", f"gs://{self._artifacts}/{digest}.json"],
                capture_output=True, text=True, timeout=120, check=True)
            return out.stdout
        raise ValueError(f"unknown detonator op: {op}")
```

Then update `resolve_trace_source` to construct `LiveSandboxSource` with settings:
change the `live = LiveSandboxSource(detonator_instance=detonator_instance)` line's call
site (and the function signature that feeds it) to pass `project`, `corpus_bucket`,
`artifacts_bucket`, `zone` from the caller. In `pipeline.py:548-551`, pass those from
`ctx.settings` (`gcp_project`, `gcs_corpus_bucket`, `gcs_artifacts_bucket`, `gcp_zone`).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_live_sandbox_source.py tests/unit/test_m3_normaliser.py -v`
Expected: PASS. Then `uv run pytest tests/contract tests/unit -q` — full suite green.

- [ ] **Step 5: Commit**

```bash
git add drishti/m3_dynamic/trace_source.py drishti/pipeline.py tests/unit/test_live_sandbox_source.py
git commit -m "feat(m3): real LiveSandboxSource over IAP; available() health probe (T4.6)"
```

---

### Task 9: Stage-1–3 gate — full suite green, lint, mypy

**Files:** none (verification task).

- [ ] **Step 1: Run the full contract+unit suite**

Run: `make test`
Expected: all pass, including the new M3 tests. Record the count.

- [ ] **Step 2: Lint and type-check**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy drishti scripts`
Expected: clean.

- [ ] **Step 3: Update STATUS.md**

Mark T4.1/T4.2/T4.6 harness-side and the containment-manifest work as DONE with the test
count and commit sha. Add a `### Deviations` note: LLM crash-repair and TLS system-CA
deferred; `emulator.py` extraction pending (Task 15). Commit.

```bash
git add STATUS.md && git commit -m "docs: M3 harness layer DONE; deviations recorded"
```

---

### Task 10: LIVE — build the detonator image  ⚠ first billable step

**Files:** none (GCP operation). **Requires operator checkpoint before starting.**

- [ ] **Step 1: Confirm auth and region**

Run:
```bash
gcloud auth list && gcloud config get account && gcloud config get project
gcloud compute instances stop instance-20260817-080247 --zone=us-east1-c --project=internship-505513
```
Expected: active account matches config; extractor VM stops (halts the larger bill).

- [ ] **Step 2: Create the build VPC with NAT**

Run:
```bash
export DRISHTI_GCP_PROJECT=cybershield-505518
gcloud compute networks create drishti-build --subnet-mode=auto --project=$DRISHTI_GCP_PROJECT
gcloud compute routers create drishti-build-router --network=drishti-build --region=us-east1 --project=$DRISHTI_GCP_PROJECT
gcloud compute routers nats create drishti-build-nat --router=drishti-build-router \
  --region=us-east1 --auto-allocate-nat-external-ip --nat-all-subnet-ip-ranges --project=$DRISHTI_GCP_PROJECT
```
Expected: network + router + NAT created.

- [ ] **Step 3: Build the image**

Run:
```bash
cd infra/gcp/packer && packer init detonator.pkr.hcl
packer build -var "project=cybershield-505518" -var "zone=us-east1-c" \
  -var "network=drishti-build" \
  -var "fixture_apk=$(pwd)/../../../canary/dist/canary.apk" \
  -var "bank_one_apk=$(pwd)/../../../canary/dist/canary.apk" \
  -var "bank_two_apk=$(pwd)/../../../canary/dist/canary.apk" \
  detonator.pkr.hcl
```
Expected: `builder_setup.sh` runs the frida import check and emulator `-version` check;
image `drishti-m3-tools-<timestamp>` created. (The bank fixtures are placeholders here;
the canary is the only committed inert APK — this is fine, they are only banking-app
fixtures for morph realism, not on the detonation path.)

- [ ] **Step 2b (if build fails):** debug ON the build VM from its own logs, one variable
  at a time (CLAUDE.md). The five known fixes (frida<17, frida-server from the module,
  `libxkbfile1`, `emulator -version` not `ldd`, no `-writable-system`) are in
  `builder_setup.sh` — do not "simplify" them. Record the image name:
```bash
gcloud compute images list --no-standard-images --project=cybershield-505518 --format='value(name)'
```

- [ ] **Step 3b: Commit any build fix** to `builder_setup.sh` with a `# FIX-N:` comment
  explaining why. `git commit -m "fix(infra): <what> on the detonator image build"`.

---

### Task 11: LIVE — create the sealed runtime VM

**Files:** none (Terraform). **Depends on Task 10 image name.**

- [ ] **Step 1: Create the runtime VPC (no NAT)**

Run:
```bash
gcloud compute networks create drishti-runtime --subnet-mode=auto --project=cybershield-505518
```
Expected: created. Do NOT add a NAT — egress denial is the safety property.

- [ ] **Step 2: Apply the detonator instance**

Run:
```bash
cd infra/gcp/terraform/runtime && terraform init
terraform apply -var "project=cybershield-505518" -var "zone=us-east1-c" -var "region=us-east1" \
  -var "network=drishti-runtime" -var "subnetwork=drishti-runtime" \
  -var "runtime_image=drishti-m3-tools-<timestamp>"
```
Read the plan before approving: confirm deny-all-egress rule, IAP-SSH allow
(`35.235.240.0/20`), `enable_nested_virtualization = true`, and **no `access_config`
block** (no external IP).

- [ ] **Step 3: Confirm no external IP**

Run: `terraform output runtime_has_external_ip`
Expected: `false`. If true, STOP — containment is not structural.

---

### Task 12: LIVE — prepare runtime and verify containment ⚠ the gate

**Files:** none (GCP operation).

- [ ] **Step 1: Start the VM and prepare it**

Run:
```bash
make lab-up
gcloud compute ssh drishti-detonator --zone=us-east1-c --project=cybershield-505518 \
  --tunnel-through-iap --command='sudo /opt/drishti/runtime_prepare.sh'
```
Expected: iptables lockdown applied, fake_c2 under mitmdump, emulator booted. If IAP
hangs, check the `35.235.240.0/20` firewall rule.

- [ ] **Step 2: Run the containment gate**

Run: `make lab-verify`
Expected: `containment verified`. This runs `verify_containment.py` on the VM: negative +
positive controls first, then `169.254.169.254:80`, `8.8.8.8:53`, `1.1.1.1:443`,
`10.0.0.1:22` all unreachable, then writes the signed manifest. **On failure it aborts —
do NOT detonate. Never downgrade a containment failure to a warning.**

- [ ] **Step 3: Confirm the manifest exists and is fresh**

Run:
```bash
gcloud compute ssh drishti-detonator --zone=us-east1-c --project=cybershield-505518 \
  --tunnel-through-iap --command='sudo cat /var/lib/drishti/containment-manifest.json'
```
Expected: a signed manifest with `"contained": true` and a recent `verified_at`.

---

### Task 13: LIVE — detonate the canary and capture the fixture

**Files:** creates `data/fixtures/traces/<sha256>.json` (committed).

- [ ] **Step 1: Detonate the inert canary**

Run (canary is `sample_kind=inert_fixture` — zero malware risk, proves the chain):
```bash
gsutil cp canary/dist/canary.apk gs://cybershield-505518-corpus/canary.apk
gcloud compute ssh drishti-detonator --zone=us-east1-c --project=cybershield-505518 \
  --tunnel-through-iap --command='sudo /opt/drishti/venv/bin/python \
  /opt/drishti/harness/dynamic_analyze.py gs://cybershield-505518-corpus/canary.apk \
  --out /opt/drishti/results/canary.json --duration 60 --sample-kind inert_fixture \
  --emulator-image drishti-m3-tools-<timestamp>'
```
Expected: `artifact=... outcome=completed|inconclusive observations=N`. This is the FIRST
execution of `hooks.js` — expect to fix overload signatures / class guards. Each fix goes
in `hooks.js` behind its `safe()` wrapper; re-run.

- [ ] **Step 2: Pull the artifact and convert to a fixture**

Run:
```bash
gsutil cp gs://cybershield-505518-artifacts/canary.json /tmp/canary.json  # or scp via IAP
uv run python -c "
from pathlib import Path
from drishti.contracts.dynamic_trace import ObservationArtifact
from drishti.m3_dynamic.trace_builder import artifact_to_trace
from drishti.contracts.dynamic_trace import TraceSourceKind
art = ObservationArtifact.model_validate_json(Path('/tmp/canary.json').read_text())
trace = artifact_to_trace(art, source=TraceSourceKind.REPLAY, vm_instance_id='drishti-detonator')
# Wrap into a captured TraceFixture with provenance.kind='captured'
print(trace.model_dump_json(indent=2))
"
```
Assemble a `TraceFixture` (see `trace_source.TraceFixture`) with
`provenance=FixtureProvenance(kind="captured", source_sha256=<sha>, captured_from_image=<image>)`,
`pre_morph=<trace dict>`, `post_morph={}`. Write to `data/fixtures/traces/<sha256>.json`.

- [ ] **Step 3: Verify replay round-trips**

Run: `uv run pytest tests/unit/test_trace_builder.py -q` and a quick replay check:
```bash
uv run python -c "
from drishti.m3_dynamic.trace_source import ReplayTraceSource
from drishti.contracts.frontier import SandboxPlan
from pathlib import Path
src = ReplayTraceSource(Path('data/fixtures/traces'))
print('available', src.available())
"
```
Expected: fixture loads, `synthetic=False`, `source=replay`.

- [ ] **Step 4: Commit the captured fixture**

```bash
git add data/fixtures/traces/<sha256>.json hooks-fixes-if-any
git commit -m "feat(m3): first captured live trace — canary, disclosed as captured replay"
```

---

### Task 14: LIVE — detonate one corpus sample, then lab-down

**Files:** none (produces an artifact in GCS + a run record in STATUS.md).

- [ ] **Step 1: Author the pilot authorization** for one x86-installable corpus sample
  (avoid ARM-only → `install_unsupported`). Write a `PilotAuthorization` JSON (see
  `dynamic_analyze.PilotAuthorization`): `sha256`, `reviewed_by`, `runtime_image`,
  `approved_at`/`expires_at`, `max_duration_s=120`.

- [ ] **Step 2: Detonate under the gate**

Run:
```bash
gcloud compute ssh drishti-detonator --zone=us-east1-c --project=cybershield-505518 \
  --tunnel-through-iap --command='sudo /opt/drishti/venv/bin/python \
  /opt/drishti/harness/dynamic_analyze.py gs://cybershield-505518-corpus/<sha>.apk \
  --out /opt/drishti/results/<sha>.json --duration 120 --sample-kind vetted_malware \
  --pilot-authorization /opt/drishti/results/pilot.json \
  --emulator-image drishti-m3-tools-<timestamp>'
```
Expected: an artifact whose `outcome` reflects real behaviour; record sha256, image
version, VM instance id, and containment manifest reference.

- [ ] **Step 3: SHUT DOWN — every time**

Run:
```bash
make lab-down
gcloud compute instances list --project=cybershield-505518
```
Expected: detonator STOPPED; no nested-virt VM left running.

- [ ] **Step 4: Record the run in STATUS.md** with measured numbers only (sample sha,
  outcome, observation count, image version). Mark T4.7 tripwire evaluated. Commit.

---

### Task 15: Extract emulator.py from the proven harness

**Files:**
- Create: `drishti/m3_dynamic/emulator.py`
- Modify: `drishti/m3_dynamic/harness.py` (delegate adb/emulator ops to `Emulator`)
- Test: `tests/unit/test_emulator.py`

**Interfaces:**
- Produces: `Emulator(serial, *, command=run_command)` with methods `wait_ready(timeout)`,
  `snapshot_load(name)`, `install(apk, attempts)`, `uninstall(package)`,
  `package_absent(package)`, `start_frida(server_path)`, `stop_frida()`. Each is the method
  of the same name currently inline in `DynamicHarness`, moved verbatim with `self.config.*`
  → constructor args.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_emulator.py
from __future__ import annotations

import subprocess

from drishti.m3_dynamic.emulator import Emulator


def _ok(*_a, **_k) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="Success", stderr="")


def test_install_success_does_not_raise() -> None:
    emu = Emulator("emulator-5554", command=_ok, sleep=lambda _s: None)
    emu.install(apk_path="/tmp/x.apk")  # no exception


def test_install_unsupported_is_classified() -> None:
    def refuse(*_a, **_k):
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="",
                                           stderr="INSTALL_FAILED_NO_MATCHING_ABIS")
    emu = Emulator("emulator-5554", command=refuse, sleep=lambda _s: None)
    import pytest
    from drishti.m3_dynamic.harness import HarnessFailure
    with pytest.raises(HarnessFailure) as exc:
        emu.install(apk_path="/tmp/x.apk")
    assert exc.value.code == "install_unsupported"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_emulator.py -v`
Expected: FAIL (module does not exist).

- [ ] **Step 3: Move the methods into `Emulator`**

Create `drishti/m3_dynamic/emulator.py` with the `Emulator` class; move `wait_for_device`
(→`wait_ready`), `restore_snapshot`(→`snapshot_load`), `install`, `package_absent`,
`start_frida`, `stop_frida` out of `DynamicHarness` verbatim, replacing `self.config.X`
with constructor parameters and `self.adb(...)` with an internal `_adb` helper. Then in
`harness.py`, have `DynamicHarness.__init__` build `self.emulator = Emulator(...)` and call
through it. Keep `HarnessFailure` in `harness.py` and import it into `emulator.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_emulator.py tests/unit/test_m3_harness.py -v`
Expected: PASS (harness tests still green — behaviour unchanged, only relocated).

- [ ] **Step 5: Commit**

```bash
git add drishti/m3_dynamic/emulator.py drishti/m3_dynamic/harness.py tests/unit/test_emulator.py
git commit -m "refactor(m3): extract Emulator class from the harness (T4.1)"
```

---

## Self-Review notes

- **Spec coverage:** §1 in-scope items 1–10 each map to Tasks 1–8 + 15; live execution
  (§3 Stage 4) to Tasks 10–14; honesty/safety (§5) enforced by Tasks 1 (signed manifest),
  5 (`synthetic=False`, provenance), 3 (redaction via ObservationEvent), 12 (containment
  gate), 13 (captured-not-live disclosure).
- **Deferred items** (LLM crash-repair, TLS system-CA, generative C2) are intentionally
  absent — recorded in Task 9 Step 3.
- **Type consistency:** `sign_manifest`/`load_and_verify_manifest`,
  `compute_detonated(techniques, hooks)`, `artifact_to_trace(artifact, *, source,
  vm_instance_id)`, `LiveSandboxSource(runner=...)`, `Emulator(serial, *, command, sleep)`
  are used identically across the tasks that produce and consume them.
- **Known risk carried into live tasks:** `hooks.js` executes for the first time in Task
  13; overload/class-guard fixes are expected and handled per-hook.
