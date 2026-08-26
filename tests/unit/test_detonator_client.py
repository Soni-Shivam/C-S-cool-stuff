"""The laptop and the VM must agree on one command surface.

`RemoteDetonatorClient` builds shell commands that `infra/gcp/detonator_run.sh` has to
understand. Nothing type-checks that seam — it is a string on one side and a `case`
statement on the other — so it is exactly where a plausible-looking client that the VM
would reject can live undetected until the one moment it matters.

That already happened once during this build: the client was written to send
`detonate --sha256 X --serial Y --duration N --morphs <json>` while the script takes
`detonate <sha> [duration]` positionally and puts pass 2 behind a *separate* `morph`
subcommand. It would have failed on the first live run, after paying for a VM start.

So these tests assert the protocol against the script itself rather than against a
remembered copy of it. No `gcloud` runs here: `_run` is patched, and what is captured is
the argv that would have been sent.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from drishti.contracts.frontier import Morph, MorphKind
from drishti.m3_dynamic import detonator as det
from drishti.m3_dynamic.detonator import (
    MORPH_SCRIPT_DIR,
    DetonatorTarget,
    DetonatorUnreachableError,
    RemoteDetonatorClient,
)

REPO = Path(__file__).resolve().parents[2]
RUN_SH = REPO / "infra" / "gcp" / "detonator_run.sh"

TARGET = DetonatorTarget(project="proj", zone="us-east1-c", instance="m3-detonator")


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Capture argv instead of running `gcloud`."""
    calls: list[list[str]] = []

    def fake_run(
        args: list[str],
        *,
        timeout: int,
        ok_returncodes: frozenset[int] = frozenset({0}),
    ) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(det, "_run", fake_run)
    return calls


def _command(sent: list[list[str]]) -> str:
    """The remote command from the last ssh invocation."""
    return next(a for a in reversed(sent[-1]) if a.startswith("--command=")).removeprefix(
        "--command="
    )


def _morph(kind: MorphKind) -> Morph:
    return Morph(kind=kind, params={}, rationale="pass 1 probed and stalled")


# ── the seam with the shell ──────────────────────────────────────────────────
def test_the_script_still_offers_the_subcommands_we_send() -> None:
    """If the shell's `case` arms are renamed, this fails before a live run does."""
    body = RUN_SH.read_text(encoding="utf-8")
    assert "detonate) shift;" in body
    assert "morph) shift;" in body


def test_pass_one_sends_positional_detonate(sent: list[list[str]]) -> None:
    RemoteDetonatorClient(TARGET).detonate("a" * 64, morphs=(), duration_s=120)
    assert _command(sent) == f"/opt/drishti/bin/detonator_run.sh detonate {'a' * 64} 120"


def test_pass_two_sends_the_morph_subcommand_with_comma_joined_kinds(
    sent: list[list[str]],
) -> None:
    """`morph <sha> <kinds> [duration]` — the script splits `kinds` on IFS=,."""
    RemoteDetonatorClient(TARGET).detonate(
        "b" * 64,
        morphs=(_morph(MorphKind.INSTALL_PACKAGES), _morph(MorphKind.SIM_LOCALE)),
        duration_s=90,
    )
    assert _command(sent) == (
        f"/opt/drishti/bin/detonator_run.sh morph {'b' * 64} install_packages,sim_locale 90"
    )


def test_duplicate_kinds_are_collapsed(sent: list[list[str]]) -> None:
    """Two morphs of one kind are one script, applied once."""
    RemoteDetonatorClient(TARGET).detonate(
        "c" * 64,
        morphs=(_morph(MorphKind.INSTALL_PACKAGES), _morph(MorphKind.INSTALL_PACKAGES)),
        duration_s=120,
    )
    assert _command(sent).endswith("install_packages 120")


def test_a_kind_with_no_script_is_refused_before_the_round_trip(sent: list[list[str]]) -> None:
    """`MorphKind` has nine values; five have scripts. The VM answers rc 5 for the rest.

    Refusing here turns an opaque exit code into a legible error, and — more importantly
    — refuses rather than quietly dropping the unsupported kind and running a pass 2
    that applied less than it claimed.
    """
    with pytest.raises(DetonatorUnreachableError, match="no morph script for contacts"):
        RemoteDetonatorClient(TARGET).detonate(
            "d" * 64, morphs=(_morph(MorphKind.CONTACTS),), duration_s=120
        )
    assert sent == [], "nothing may be sent when the plan cannot be applied"


def test_every_kind_we_advertise_as_runnable_has_a_script() -> None:
    """The laptop-side script set is what the check is made against, so it must exist."""
    available = {p.stem for p in MORPH_SCRIPT_DIR.glob("*.js")}
    assert available, "the morph script directory is empty"
    assert available <= {k.value for k in MorphKind}, "a script names a kind the enum lacks"


# ── collection reads the right half ──────────────────────────────────────────
def test_pass_one_and_pass_two_read_different_artifacts(
    sent: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`morph` writes `<sha>.morph.json`; reading `<sha>.json` would replay pass 1."""
    client = RemoteDetonatorClient(TARGET)
    with pytest.raises(DetonatorUnreachableError):  # empty stdout -> no artifact
        client.collect("e" * 64, morphed=False)
    assert _command(sent).endswith(f"/opt/drishti/results/{'e' * 64}.json")

    with pytest.raises(DetonatorUnreachableError):
        client.collect("e" * 64, morphed=True)
    assert _command(sent).endswith(f"/opt/drishti/results/{'e' * 64}.morph.json")


# ── refusals ─────────────────────────────────────────────────────────────────
def test_an_unconfigured_client_reports_rather_than_calling_gcloud(sent: list[list[str]]) -> None:
    assert RemoteDetonatorClient(target=None).instance_state() == "UNCONFIGURED"
    assert sent == []


def test_staging_without_a_lab_refuses(tmp_path: Path, sent: list[list[str]]) -> None:
    with pytest.raises(DetonatorUnreachableError, match="no detonator configured"):
        RemoteDetonatorClient(target=None).stage(tmp_path / "x.apk", "f" * 64)
    assert sent == []


def test_collect_reads_a_root_owned_artifact(
    sent: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`dynamic_analyze.py` runs under `as_root`, so its artifact lands root:root 0600.

    MEASURED 2026-08-26 on `m3-detonator`: the first live run through the pipeline
    staged and detonated correctly, then `collect()` came back
    `PermissionError: [Errno 13] ... /opt/drishti/results/<sha>.json`. The batch path
    never hit it because `detonator_collect.sh` chowns the directory first; this path
    reads one file directly and must elevate for itself.
    """
    client = RemoteDetonatorClient(TARGET)
    with pytest.raises(DetonatorUnreachableError):  # empty stdout -> no artifact
        client.collect("e" * 64, morphed=False)
    assert _command(sent).startswith("sudo cat "), (
        "collect() must read the artifact as root; a plain cat is a permission error"
    )


def test_a_failure_message_keeps_the_end_of_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    """gcloud puts boilerplate first and the actual error last.

    MEASURED 2026-08-26: every IAP call prints a ~200-character "consider installing
    NumPy" banner on stderr before anything useful. Truncating the *head* to 400 chars
    kept the banner and discarded the reason, so two consecutive failed detonations
    both surfaced as `DetonatorUnreachableError: WARNING:` and the real message —
    "another detonation is already running" — never reached the log.

    Exercises the real `_run`, so it deliberately does not take the `sent` fixture.
    """
    banner = "WARNING: \n\nTo increase the performance of the tunnel, " + "x" * 380
    real = "another detonation is already running"

    def fake_run(args, **kwargs):  # noqa: ANN001, ANN003, ARG001
        return subprocess.CompletedProcess(args, 1, stdout="", stderr=f"{banner}\n{real}\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(DetonatorUnreachableError) as excinfo:
        RemoteDetonatorClient(TARGET).detonate("a" * 64, morphs=(), duration_s=1)
    assert real in str(excinfo.value), "the end of stderr is where the reason lives"


def test_an_unsafe_artifact_is_not_an_unreachable_detonator(monkeypatch: pytest.MonkeyPatch) -> None:
    """`dynamic_analyze.py` exits 2 for a run that happened but is unsafe to ingest.

    MEASURED 2026-08-26 on `m3-detonator` with an ARM64-only APK: containment verified,
    the artifact written with an honest `install_unsupported` failure, snapshot restored
    clean before and after — and `dynamic_analyze.py:125` still returned 2, because
    `safe_for_ingestion` requires `outcome in {completed, inconclusive}`.

    Treating that as a transport failure raised `DetonatorUnreachableError` before
    `collect()` ever ran, so `LiveSandboxSource.run`'s specific gate — the one that
    names `outcome=failed` — was unreachable, and the pipeline substituted a synthetic
    stub asserting `containment_verified=False` over a signed manifest that said the
    opposite. rc 2 must return normally and let the gates read the artifact.
    """
    seen: list[int] = []

    def fake_run(args, **kwargs):  # noqa: ANN001, ANN003, ARG001
        seen.append(1)
        return subprocess.CompletedProcess(args, 2, stdout="artifact=... outcome=failed\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    # Must not raise: the detonation ran, and only the artifact can say whether it counts.
    RemoteDetonatorClient(TARGET).detonate("a" * 64, morphs=(), duration_s=1)
    assert len(seen) == 1, "rc 2 must not be retried as a transport failure"


def test_a_real_transport_failure_still_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only rc 2 is special. rc 3 (`sample not staged`) is still a failure."""

    def fake_run(args, **kwargs):  # noqa: ANN001, ANN003, ARG001
        return subprocess.CompletedProcess(args, 3, stdout="", stderr="sample not staged")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(DetonatorUnreachableError, match="sample not staged"):
        RemoteDetonatorClient(TARGET).detonate("a" * 64, morphs=(), duration_s=1)
