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

    def fake_run(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
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
