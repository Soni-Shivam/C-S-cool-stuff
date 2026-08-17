# Ledger Concurrency Hardening & Reality Reconciliation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three defects that make the evidence ledger unverifiable on a fresh install under concurrency, and correct `STATUS.md`/`PROGRESS.md` so they stop asserting infrastructure that no longer exists.

**Architecture:** Three independent bug fixes in `drishti/ledger/crypto.py`, `drishti/api/jobs.py`, and `drishti/ledger/store.py`, each with a failing test written first. Then a documentation-only reconciliation task. No new modules, no contract changes, no dependency changes.

**Tech Stack:** Python 3.11, pytest, `cryptography` (Ed25519), SQLite, `uv`, `ruff`, `mypy`.

## Global Constraints

- Python **3.11** for the app; anything that also runs on the GCE VM must import cleanly on **3.10**.
- `ruff` formatted; type hints on all public functions; `*.md` is excluded from `ruff` (do not reformat specs).
- Docstrings on public functions state **what**, not how.
- Contracts are pydantic models in `drishti/contracts/`. **Never pass a raw dict across a module boundary.** No contract changes in this plan.
- `ChainVerification` is an existing contract in `drishti/contracts/evidence.py` — its *fields* are unchanged by this plan; only the values `verify_chain()` returns change.
- Every PR: `uv run pytest tests/contract tests/unit` green, `uv run ruff check .` clean, `uv run ruff format --check .` clean, `uv run mypy drishti` clean.
- Commit style: `fix(ledger): ...`, `fix(api): ...`, `docs: ...`.
- **Never weaken a test to make it pass.** A skipped or loosened test is reported, not worked around.
- All commands run from the repo root with `export PATH="$HOME/.local/bin:$PATH"` so `uv` resolves.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `drishti/ledger/crypto.py` | Canonicalisation, hashing, Ed25519 key lifecycle | Modify: `load_or_create_key` becomes atomic; add `_read_key`, `LedgerKeyError` |
| `drishti/api/jobs.py` | In-process job runner | Modify: `_run` constructs the ledger inside its own `try` |
| `drishti/ledger/store.py` | Append-only store + chain verification | Modify: `verify_chain` rejects an empty chain |
| `tests/unit/test_ledger_key_concurrency.py` | **Create** — proves one key survives N racing creators | New |
| `tests/unit/test_job_runner_failure_paths.py` | **Create** — proves a worker never dies silently | New |
| `tests/contract/test_ledger_chain.py` | Existing chain-verification contract tests | Modify: add empty-chain case |
| `STATUS.md` | Current state of the world | Modify: reconcile with verified reality |
| `PROGRESS.md` | Narrative log | Modify: add entry; correct PR references |

---

### Task 1: Atomic ledger signing-key creation

**Files:**
- Modify: `drishti/ledger/crypto.py:80-114` (`load_or_create_key`)
- Test: `tests/unit/test_ledger_key_concurrency.py` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `crypto.load_or_create_key(path: Path) -> Ed25519PrivateKey` — unchanged signature, now safe under concurrency. New public exception `crypto.LedgerKeyError(Exception)`, raised when the key file exists but cannot be read as an Ed25519 key. Task 2's test relies on `load_or_create_key` not raising under normal conditions.

**Why:** `load_or_create_key` does check-then-act. Two `LedgerStore` instances constructed concurrently (the default `job_workers=2`) both see no file, both generate a key, both write, last writer wins — and the loser returns an in-memory key that is not on disk. Every node it signs fails verification forever. A second interleaving lets a reader see a half-written PEM.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_ledger_key_concurrency.py`:

```python
"""The signing key must be created exactly once, however many creators race.

docs/superpowers/plans/2026-08-17-ledger-hardening-and-reconciliation.md Task 1.

If two threads each generate a key and the second overwrites the first, the first
thread's nodes are signed with a key that no longer exists on disk and the chain can
never verify. That is unrecoverable: the evidence is not re-signable.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from drishti.ledger import crypto

RACERS = 8


def test_concurrent_creation_yields_exactly_one_key(tmp_path: Path) -> None:
    key_path = tmp_path / "ledger_ed25519.key"
    barrier = threading.Barrier(RACERS)
    seen: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        # Release every thread at the same instant to maximise the overlap.
        barrier.wait()
        key = crypto.load_or_create_key(key_path)
        with lock:
            seen.append(crypto.public_key_hex(key))

    threads = [threading.Thread(target=worker) for _ in range(RACERS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(seen) == RACERS
    assert len(set(seen)) == 1, f"{len(set(seen))} distinct keys were created, expected 1"

    # The key every caller returned must be the one that is actually on disk.
    on_disk = crypto.public_key_hex(crypto.load_or_create_key(key_path))
    assert set(seen) == {on_disk}


def test_existing_key_is_reused(tmp_path: Path) -> None:
    key_path = tmp_path / "ledger_ed25519.key"
    first = crypto.public_key_hex(crypto.load_or_create_key(key_path))
    second = crypto.public_key_hex(crypto.load_or_create_key(key_path))
    assert first == second


def test_key_file_is_owner_only(tmp_path: Path) -> None:
    key_path = tmp_path / "ledger_ed25519.key"
    crypto.load_or_create_key(key_path)
    assert key_path.stat().st_mode & 0o077 == 0, "signing key must not be group/world readable"


def test_unreadable_key_file_raises_rather_than_regenerating(tmp_path: Path) -> None:
    """Silently regenerating would invalidate every chain already signed.

    An operator deleting a corrupt key is a decision; a library making it silently is
    evidence destruction.
    """
    key_path = tmp_path / "ledger_ed25519.key"
    key_path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot actually a key\n")
    with pytest.raises(crypto.LedgerKeyError):
        crypto.load_or_create_key(key_path)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `export PATH="$HOME/.local/bin:$PATH" && uv run pytest tests/unit/test_ledger_key_concurrency.py -v`

Expected: `test_concurrent_creation_yields_exactly_one_key` FAILS with something like
`AssertionError: 4 distinct keys were created, expected 1`, and
`test_unreadable_key_file_raises_rather_than_regenerating` FAILS with
`AttributeError: module 'drishti.ledger.crypto' has no attribute 'LedgerKeyError'`.
The other two may already pass — that is fine and expected.

- [ ] **Step 3: Implement the atomic creation**

In `drishti/ledger/crypto.py`, add `threading` to the imports at the top (it already imports `hashlib`, `json`, `os`, `Path`, `Any`):

```python
import threading
```

Add the exception below `FLOAT_PRECISION`:

```python
class LedgerKeyError(Exception):
    """The signing key file exists but is not a usable Ed25519 private key.

    Deliberately fatal. Regenerating would leave every previously signed node
    unverifiable, so replacing a corrupt key is an operator decision.
    """
```

Replace the whole of `load_or_create_key` (currently lines 80–114) with:

```python
def _read_key(path: Path) -> Ed25519PrivateKey | None:
    """Return the key at `path`, or None if there is nothing there yet.

    A zero-length file counts as absent: that is what a crash mid-create leaves
    behind, and it is the one corrupt state it is safe to overwrite.
    """
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    if not raw:
        return None
    try:
        loaded = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError) as exc:
        raise LedgerKeyError(f"{path} is not a readable PEM private key: {exc}") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise LedgerKeyError(f"{path} is not an Ed25519 private key: {type(loaded).__name__}")
    return loaded


def load_or_create_key(path: Path) -> Ed25519PrivateKey:
    """Load a PEM Ed25519 private key, generating and persisting one if absent.

    Safe against concurrent creators. The previous check-then-act version let two
    threads each generate a key and the second overwrite the first, so the first
    thread signed nodes with a key that was no longer on disk and its chain could
    never verify.

    v1 left `LEDGER_SIGNING_KEY` empty, so a fresh key was generated per run and
    chains from different runs could not be compared against a stable public key
    (docs/CARRIED_FINDINGS.md H8). Persisting on first use fixes that.

    The file is written `0600`. It is unencrypted at rest because a passphrase we
    would have to store next to it buys nothing; the threat model here is evidence
    tampering, not key theft from an already-compromised analysis host.
    """
    path = Path(path)
    existing = _read_key(path)
    if existing is not None:
        return existing

    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Create with restrictive permissions rather than chmod-ing afterwards, so the
    # key is never briefly world-readable.
    # `Path.open()` has no `opener` parameter — only the builtin does.
    def _private_opener(target: str, flags: int) -> int:
        return os.open(target, flags, 0o600)

    # Write to a uniquely-named temp file in the same directory, fsync it, then
    # hard-link it into place. os.link raises FileExistsError if the destination
    # exists, which makes "create only if absent" a single atomic step instead of a
    # check followed by a write. Same directory so the link cannot cross a
    # filesystem boundary.
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with open(tmp, "wb", opener=_private_opener) as handle:
            handle.write(pem)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            # Another creator won. Theirs is the key of record.
            pass
    finally:
        tmp.unlink(missing_ok=True)

    # Always re-read. Whoever won the link race owns the key on disk and every caller
    # must return that one — returning our in-memory key after losing the race is
    # precisely the bug this function used to have.
    winner = _read_key(path)
    if winner is None:
        raise LedgerKeyError(f"failed to create or read a signing key at {path}")
    return winner
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `export PATH="$HOME/.local/bin:$PATH" && uv run pytest tests/unit/test_ledger_key_concurrency.py -v`
Expected: 4 passed.

- [ ] **Step 5: Run the full suite and static checks**

Run:
```bash
export PATH="$HOME/.local/bin:$PATH" && uv run pytest tests/contract tests/unit -q && uv run ruff check . && uv run ruff format --check . && uv run mypy drishti
```
Expected: all green. Note the new total test count — it goes into `STATUS.md` in Task 4.

- [ ] **Step 6: Commit**

```bash
git add drishti/ledger/crypto.py tests/unit/test_ledger_key_concurrency.py
git commit -m "fix(ledger): create the signing key atomically

load_or_create_key did check-then-act, so two LedgerStore instances built
concurrently (job_workers defaults to 2) both generated a key and the second
overwrote the first. The losing thread returned an in-memory key that was not on
disk, and every node it signed failed verification permanently. A second
interleaving let a reader see a half-written PEM.

Write to a temp file, fsync, then os.link into place — link fails if the
destination exists, making create-if-absent atomic — and always re-read so every
caller converges on whichever key won.

A corrupt key file now raises LedgerKeyError instead of being silently replaced;
regenerating would invalidate every chain already signed."
```

---

### Task 2: A worker thread must never die silently

**Files:**
- Modify: `drishti/api/jobs.py:106-133` (`JobRunner._run`)
- Test: `tests/unit/test_job_runner_failure_paths.py` (create)

**Interfaces:**
- Consumes: `crypto.load_or_create_key` from Task 1 (no longer raises on a torn read).
- Produces: no signature changes. `JobRunner._run` guarantees that `_DONE` is published and the job reaches `JobStage.FAILED` on any exception, including one raised while constructing `LedgerStore`.

**Why:** `_run`'s docstring says *"Must never raise — a dead worker thread is a silent hang."* But `ledger = LedgerStore(...)` sits **above** the `try`, so an exception there skips both the `except` that marks the job `FAILED` and the `finally` that publishes `_DONE`. The SSE consumer then blocks for the full `timeout_s` and the job is stuck in `QUEUED` forever.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_job_runner_failure_paths.py`:

```python
"""A worker thread that dies must still end the job and close the stream.

docs/superpowers/plans/2026-08-17-ledger-hardening-and-reconciliation.md Task 2.

JobRunner._run promises in its docstring that it never raises. The ledger was being
constructed above the try block, so a failure there skipped both the handler that
marks the job FAILED and the finally that publishes the done sentinel — leaving the
SSE consumer to block until its timeout on a job that would never progress.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from drishti.api.jobs import JobRunner
from drishti.config import Settings
from drishti.contracts.job import JobStage
from tests.apk_fixtures import minimal_apk_bytes


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "drishti.db",
        ledger_key_path=tmp_path / "key.pem",
        log_path=tmp_path / "log.jsonl",
        llm_provider="mock",
        job_workers=2,
    )


@pytest.fixture
def apk(tmp_path: Path) -> Path:
    path = tmp_path / "sample.apk"
    path.write_bytes(minimal_apk_bytes())
    return path


def test_ledger_construction_failure_fails_the_job_and_closes_the_stream(
    settings: Settings, apk: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("ledger unavailable")

    monkeypatch.setattr("drishti.api.jobs.LedgerStore", explode)

    runner = JobRunner(settings)
    try:
        job = runner.submit(apk, "sample.apk")

        started = time.monotonic()
        # If the sentinel is never published this blocks for the full timeout.
        list(runner.stream(job.id, timeout_s=10))
        elapsed = time.monotonic() - started
        assert elapsed < 5, f"stream blocked {elapsed:.1f}s — the done sentinel was not published"

        current = runner.get(job.id)
        assert current is not None
        assert current.stage is JobStage.FAILED
        assert current.error is not None
        assert "ledger unavailable" in current.error
    finally:
        runner.shutdown()


def test_two_concurrent_jobs_on_a_fresh_db_both_verify(settings: Settings, apk: Path) -> None:
    """The regression this whole plan exists for.

    Two jobs submitted at once against a database and key that do not yet exist. Both
    chains must verify against the key that ends up on disk.
    """
    from drishti.ledger.store import LedgerStore

    runner = JobRunner(settings)
    try:
        first = runner.submit(apk, "one.apk")
        second = runner.submit(apk, "two.apk")
        list(runner.stream(first.id, timeout_s=30))
        list(runner.stream(second.id, timeout_s=30))

        store = LedgerStore(settings.db_path, settings.ledger_key_path)
        try:
            for job_id in (first.id, second.id):
                result = store.verify_chain(job_id)
                assert result.ok is True, f"{job_id}: {result.reason}"
                assert result.node_count > 0
        finally:
            store.close()
    finally:
        runner.shutdown()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `export PATH="$HOME/.local/bin:$PATH" && uv run pytest tests/unit/test_job_runner_failure_paths.py -v`

Expected: `test_ledger_construction_failure_fails_the_job_and_closes_the_stream` FAILS —
either on `stream blocked 10.0s — the done sentinel was not published`, or on
`assert current.stage is JobStage.FAILED` finding `JobStage.QUEUED`.
`test_two_concurrent_jobs_on_a_fresh_db_both_verify` should PASS already, because Task 1
fixed its root cause — it is here as a permanent regression guard.

- [ ] **Step 3: Move ledger construction inside the try**

In `drishti/api/jobs.py`, replace the body of `_run` (currently lines 106–133) with:

```python
    def _run(self, job: Job, apk_path: Path) -> None:
        """Worker body. Must never raise — a dead worker thread is a silent hang.

        Everything fallible lives inside the try, including opening the ledger. When
        that construction sat above it, a failure there skipped both the handler that
        marks the job FAILED and the finally that publishes the done sentinel.
        """
        ledger: LedgerStore | None = None
        try:
            # A per-job ledger connection: sqlite3 connections are not shareable
            # across threads, and WAL means the concurrent reader is unaffected.
            ledger = LedgerStore(self._settings.db_path, self._settings.ledger_key_path)
            with self._lock:
                artefacts = self._artefacts.setdefault(job.id, {})
            # The same dict object the API reads, so a stage's output is visible the
            # instant it is recorded rather than after the run.
            ctx = Context(
                settings=self._settings,
                ledger=ledger,
                on_event=lambda event: self._publish(job.id, event),
                artefacts=artefacts,
            )
            finished = run_pipeline(job, ctx, apk_path=apk_path)
            self._store(finished)
        except BaseException as exc:  # noqa: BLE001 - a worker must not propagate
            log.error("job_crashed", job_id=job.id, error=str(exc), exc_info=True)
            with self._lock:
                current = self._jobs.get(job.id, job)
                self._jobs[job.id] = current.model_copy(
                    update={"stage": JobStage.FAILED, "error": f"runner: {exc}"}
                )
        finally:
            if ledger is not None:
                ledger.close()
            self._publish(job.id, _DONE)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `export PATH="$HOME/.local/bin:$PATH" && uv run pytest tests/unit/test_job_runner_failure_paths.py -v`
Expected: 2 passed.

- [ ] **Step 5: Run the full suite and static checks**

Run:
```bash
export PATH="$HOME/.local/bin:$PATH" && uv run pytest tests -q && uv run ruff check . && uv run ruff format --check . && uv run mypy drishti
```
Expected: all green, **including `tests/e2e`** — `test_two_concurrent_jobs_keep_separate_chains` should now pass in isolation. Verify that specifically:

```bash
uv run pytest tests/e2e/test_pipeline_walk.py::test_two_concurrent_jobs_keep_separate_chains -v
```
Expected: PASS (it failed 3/3 before Task 1).

- [ ] **Step 6: Commit**

```bash
git add drishti/api/jobs.py tests/unit/test_job_runner_failure_paths.py
git commit -m "fix(api): a worker thread can no longer die before publishing _DONE

_run's docstring promised it never raises, but LedgerStore was constructed above
the try, so a failure there skipped both the handler that marks the job FAILED and
the finally that publishes the done sentinel. The SSE consumer then blocked for the
full timeout on a job permanently stuck in QUEUED.

Construct the ledger inside the try and close it defensively in the finally."
```

---

### Task 3: An empty chain must not verify

**Files:**
- Modify: `drishti/ledger/store.py:292-344` (`verify_chain`)
- Test: `tests/contract/test_ledger_chain.py` (modify — append the new tests)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `LedgerStore.verify_chain(job_id: str | None = None) -> ChainVerification` — unchanged signature. Behaviour change: a job with zero nodes now returns `ok=False, node_count=0, first_bad_seq=None, reason="empty chain: no nodes for job '<id>'"`. `drishti/ledger/cli.py`'s verify command consequently exits 1 for an empty job.

**Why:** `verify_chain` returns `ChainVerification(ok=True, node_count=0)` when the loop body never executes. Demo beat #7 (`00_GUIDING_MAP.md §2`) is *"show `verify_chain()` returning green"*. Green on a job that produced nothing is a vacuous pass — the same defect class as v1's `nc -z` bug, where `blocked()` returned `True` unconditionally and a signed manifest attested containment that had never been tested (`CLAUDE.md §Containment verification is a test, not a claim`).

- [ ] **Step 1: Write the failing test**

Append to `tests/contract/test_ledger_chain.py`:

```python
def test_empty_chain_does_not_verify(tmp_path: Path) -> None:
    """"Nothing to verify" is not "verified".

    A vacuous pass here would let the demo's verify_chain beat go green on a job that
    produced no evidence at all.
    """
    store = LedgerStore(tmp_path / "ledger.db", tmp_path / "key.pem")
    try:
        result = store.verify_chain("job_that_never_ran")
        assert result.ok is False
        assert result.node_count == 0
        assert result.first_bad_seq is None
        assert result.reason is not None
        assert "no nodes" in result.reason
    finally:
        store.close()


def test_chain_with_one_node_still_verifies(tmp_path: Path) -> None:
    """Guard the boundary: rejecting empty must not reject a single-node chain."""
    store = LedgerStore(tmp_path / "ledger.db", tmp_path / "key.pem")
    try:
        store.open("job_single")
        store.append(
            type=EvidenceType.FILE_META,
            source_tool="test",
            content={"sha256": "a" * 64},
        )
        result = store.verify_chain("job_single")
        assert result.ok is True
        assert result.node_count == 1
    finally:
        store.close()
```

That file already imports `EvidenceType` and `LedgerStore`. It does **not** import
`Path` — add it to the stdlib import block, so the block reads:

```python
import itertools
import json
import sqlite3
from pathlib import Path
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `export PATH="$HOME/.local/bin:$PATH" && uv run pytest tests/contract/test_ledger_chain.py -v -k "empty_chain or one_node"`

Expected: `test_empty_chain_does_not_verify` FAILS with `assert True is False`.
`test_chain_with_one_node_still_verifies` PASSES already.

- [ ] **Step 3: Reject the empty chain**

In `drishti/ledger/store.py`, inside `verify_chain`, insert the guard immediately after `rows` is built and before `pubkey` is computed:

```python
        if not rows:
            # "Nothing to verify" is not "verified". A caller showing this result to a
            # human — the UI badge, the CLI, the report — must not read green for a
            # job that produced no evidence at all.
            return ChainVerification(
                ok=False,
                node_count=0,
                first_bad_seq=None,
                reason=f"empty chain: no nodes for job {job_id!r}",
            )
```

Also extend the method's docstring with a line recording the rule:

```
        An empty chain is reported as NOT ok: a job that produced no evidence has
        nothing to attest, and a vacuous green here would be indistinguishable from a
        real one.
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `export PATH="$HOME/.local/bin:$PATH" && uv run pytest tests/contract/test_ledger_chain.py -v`
Expected: all pass.

- [ ] **Step 5: Check every caller for a behaviour change**

Run:
```bash
export PATH="$HOME/.local/bin:$PATH"
grep -rn "verify_chain" drishti/ tests/ --include=*.py
uv run pytest tests -q
```
Expected: full suite green. If any test asserted `ok is True` for a job with no nodes, that assertion was encoding the bug — fix the test to expect `ok is False`, and note it in the commit body. **Do not** relax the new guard to keep an old test passing.

- [ ] **Step 6: Commit**

```bash
git add drishti/ledger/store.py tests/contract/test_ledger_chain.py
git commit -m "fix(ledger): an empty chain no longer verifies as OK

verify_chain returned ok=True, node_count=0 when the loop body never ran. Demo
beat #7 is showing verify_chain green, and green on a job that produced no
evidence is a vacuous pass — the same shape as v1's nc -z bug, where blocked()
returned True unconditionally and a signed manifest attested containment that was
never tested.

Empty now returns ok=False with an explicit reason. The single-node boundary is
tested so the guard cannot over-reach."
```

---

### Task 4: Reconcile `STATUS.md` and `PROGRESS.md` with verified reality

**Files:**
- Modify: `STATUS.md`
- Modify: `PROGRESS.md`

**Interfaces:**
- Consumes: the test counts produced by Tasks 1–3 (`uv run pytest tests` total).
- Produces: nothing code-facing.

**Why:** `00_GUIDING_MAP.md §13` makes `STATUS.md` the technical appendix of the pitch. It currently asserts a GCP project, buckets, snapshots, and rescued artifacts that do not exist, an unqualified `304/304` test count, and merged PRs #1–#11 that are absent from the remote. A judge running `gcloud projects list` against it finds a contradiction.

- [ ] **Step 1: Gather the real numbers**

Run and record the output of each:
```bash
export PATH="$HOME/.local/bin:$PATH"
uv run pytest tests/contract tests/unit -q 2>&1 | tail -2      # contract+unit count
uv run pytest tests -q 2>&1 | tail -2                          # total count
uv run mypy drishti 2>&1 | tail -1                             # files checked
git log --oneline -1                                           # current sha
```

- [ ] **Step 2: Replace the "Verified environment facts" table in `STATUS.md`**

Replace the existing table (currently rows for GCP v1/v2, Secrets, v1 corpus list, Test baseline) with:

```markdown
## Verified environment facts

Re-established by inspection on 2026-08-17. Every row was checked with a command.

| Item | State |
|---|---|
| GCP (v1, legacy `drishti-m3-08130038`) | **GONE.** Not present in `gcloud projects list`; `describe` returns permission-denied/absent. All four rescue snapshots went with it |
| GCP (v2 `drishti-v2-260814`) | **GONE.** Same. The corpus bucket, artifacts bucket, `samples.csv`, and the 14 rescued v1 detonation artifacts are **unrecoverable** |
| Trial billing account | `01996C-C72085-6358D2`, **`open: false`** (closed) |
| Usable billing account | `017B2F-A06E63-B76B98`, INR, `open: true` |
| GCP (v3) | **`cybershield-505518`**, billing linked. compute/storage/oslogin enabled; **IAP not yet enabled**. **0 VMs, 0 buckets** |
| Compute quota | `CPUS_ALL_REGIONS: 32`, `asia-south1 CPUS: 100`, `DISKS_TOTAL_GB: 4096`, `INSTANCES: 24` — no increase needed |
| Extractor VM (pre-existing) | `instance-20260817-080247`, project `internship-505513`, `us-east1-c`, `n2-standard-2`, 500GB `pd-standard`, **public IP**, **nested virt OFF**, SA scope `devstorage.read_only` |
| Secrets | `.env` recreated (gitignored). `ANDROZOO_API_KEY` set — **exposed in a chat transcript, rotate post-demo**. `GEMINI_API_KEY` **not yet provided** |
| PR trail | **Zero PRs exist on the remote.** `PROGRESS.md`'s references to PRs #1–#11 describe local branch history only |
| Test baseline | Measured 2026-08-17 — see the per-task counts below. v1's claimed 124 is still unverified; do not quote it |
```

- [ ] **Step 3: Update the P0 and salvage sections in `STATUS.md`**

Change the salvage block so items that depended on the dead projects read `LOST`, not `TODO`:

```markdown
## Salvage from v1 (see `docs/SALVAGE.md`)

- [x] known_bad_hashes.txt LIFT -> data/kb/                 DONE  H07
- [x] Lab infra LIFT (`infra/m3/**` → `infra/gcp/`)        DONE  H08
- [ ] Containment verification LIFT                        TODO
- [ ] M3 harness + hook catalogue LIFT                     TODO
- [~] canary/ source written to §4 spec                    WIP   needs JDK 17
- [x] ~~Rescue v1 lab data off VM disks → GCS~~            **LOST**  2026-08-17
      Both GCP projects were deleted. The 4 boot-disk snapshots, the 14 rescued
      observation artifacts, the 3 attestations and `samples.csv` are gone with them.
      **Surviving provenance:** the 2 observation artifacts committed as CI fixtures
      at `data/fixtures/observations/`, and the measurements in
      `docs/CARRIED_FINDINGS.md`. Those are now the only v1 evidence that exists.
```

Add to `## Decisions`:

```markdown
| 2026-08-17 | Lab rebuilt in **`cybershield-505518`**, region **`us-east1`** | Co-located with the pre-existing extractor VM; cross-region would cost ~$12 to move 120GB. Deviates from CLAUDE.md's `asia-south1` |
| 2026-08-17 | Extractor = the existing `internship-505513` VM; **detonator built separately and sealed** | Static parsing never executes a sample, so a shared project is acceptable there. Detonation is not: that VM has no nested virt, a public IP, and shares a VPC with an unrelated live VM |
```

Add to `## Open risks`:

```markdown
- **All v1 GCP provenance is unrecoverable** (2026-08-17). Any claim that rests on the
  9-sample v1 pilot is now supported only by 2 committed fixtures plus
  `CARRIED_FINDINGS.md`. Do not present the other 12 artifacts as available evidence.
- **The AndroZoo API key was exposed in a chat transcript.** Rotate after the demo.
- **`GEMINI_API_KEY` is not set.** P3 is blocked on it; `mock` covers tests until then.
```

- [ ] **Step 4: Add the `PROGRESS.md` entry**

Insert immediately below the `Conventions:` block, above the existing newest entry, substituting the real numbers recorded in Step 1:

```markdown
## 2026-08-17 · Ledger concurrency hardening + reality reconciliation

**Phase:** P0 · Plan: `docs/superpowers/plans/2026-08-17-ledger-hardening-and-reconciliation.md`

Establishing a real test baseline surfaced three defects, one root cause behind two of
them. The e2e suite had never been run alongside the others, so none had been seen.

### Found

**1. The ledger signing key was created non-atomically.** `load_or_create_key` did
check-then-act, so two `LedgerStore` instances built concurrently — and `job_workers`
defaults to 2 — both generated a key and the second overwrote the first. The losing
thread signed every one of its nodes with a key that was not on disk. **On a fresh
install, the first two concurrent uploads produced a permanently unverifiable ledger,
and the evidence is not re-signable.** Reproduced 3/3 in isolation:
`first_bad_seq=0, "signature is not valid for this node_hash"`.

**2. Same root cause, second symptom.** A reader could catch a half-written PEM.
`LedgerStore.__init__` then raised from *above* `JobRunner._run`'s try block, so the
worker died without marking the job `FAILED` and without publishing `_DONE` — the SSE
consumer blocked for its full timeout on a job stuck in `QUEUED`. This is why the
failure looked like a flaky `node_count=0` rather than a signature problem.

**3. An empty chain verified as OK.** `verify_chain` returned `ok=True, node_count=0`
when the loop body never ran. Demo beat #7 is showing that call green. Same shape as
v1's `nc -z` bug: a check that passes because it never actually ran.

**4. `STATUS.md` asserted infrastructure that no longer exists.** Both GCP projects are
gone, taking the rescued v1 artifacts, the corpus, and all four snapshots. The trial
billing account is closed. The PRs `PROGRESS.md` cites were never on the remote.

### Verified

Two jobs submitted concurrently against a database and key that do not yet exist now
both verify. `test_concurrent_creation_yields_exactly_one_key` races 8 threads through
a barrier and asserts a single key survives.

### Not verified

- **No GCP resource was created or touched in this work.** Laptop only.
- Nothing was detonated, and no sample was analysed.
- The fix is tested against threads, not processes. Two *processes* racing are also
  handled — `os.link` is atomic across processes — but there is no test for it.
```

- [ ] **Step 5: Correct the PR references in `PROGRESS.md`**

The existing entries cite `**PR:** #7 (merged)`, `#8`, `#9`, `#10`, `#11`. Add this line directly under the `Conventions:` bullet list so the entries are not silently wrong:

```markdown
- **PR numbers below refer to local branch history.** `gh pr list --state all` on the
  remote returns nothing; no pull request was ever opened against
  `Soni-Shivam/CyberShield`. Verified 2026-08-17.
```

- [ ] **Step 6: Verify the docs did not get reformatted and commit**

Run:
```bash
export PATH="$HOME/.local/bin:$PATH"
uv run ruff format --check .    # *.md is excluded; this must stay clean
git diff --stat
```
Expected: only `STATUS.md` and `PROGRESS.md` changed.

```bash
git add STATUS.md PROGRESS.md
git commit -m "docs: reconcile STATUS.md with verified 2026-08-17 reality

Both GCP projects are gone, and the rescued v1 artifacts, corpus, snapshots and
samples.csv went with them — those rows now read LOST rather than TODO, and the
surviving provenance is named explicitly so nothing overstates what is left.

Also: the trial billing account is closed, the PRs PROGRESS.md cites were never
opened on the remote, and the test baseline is re-measured rather than inherited.

STATUS.md is the technical appendix of the pitch (00_GUIDING_MAP.md 13). It has to
survive a judge running gcloud projects list next to it."
```

---

## Definition of Done

- [ ] `uv run pytest tests` fully green, **including `tests/e2e`**
- [ ] `tests/e2e/test_pipeline_walk.py::test_two_concurrent_jobs_keep_separate_chains` passes **in isolation** (it failed 3/3 before)
- [ ] `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy drishti` all clean
- [ ] `STATUS.md` contains no claim contradicted by `gcloud projects list`
- [ ] Branch pushed, PR opened, CI green, merged
- [ ] Real test counts recorded in `STATUS.md`

## Out of scope

T0.8 (UI shell) and T0.9 (canary APK) close out P0 but are a separate plan — they need a JDK 17 install and a greenfield Vite app, and neither shares code with this one. No GCP resource is created by this plan.
