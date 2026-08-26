"""Drive the sealed GCE detonator over IAP. Executes nothing locally, ever.

docs/PHASE_4_DYNAMIC_SANDBOX.md T4.1-T4.3, docs/M3_DETONATOR_RUNBOOK.md.

The runbook's flow existed only as shell a human typed in order: `detonator_stage.sh`,
then `detonator_run.sh detonate`, then `detonator_collect.sh`. That works for a batch and
cannot work for a job the API accepted thirty seconds ago, so this module is the same
sequence expressed as something `LiveSandboxSource` can call.

**The split this file exists to protect** is CLAUDE.md's one stated rule: a file under
`data/samples/` is never opened by an installer, an emulator, or a `subprocess` on a
developer machine. Every method here therefore issues a *remote* command — `gcloud
compute ssh --tunnel-through-iap`, `gcloud compute scp` — and there is deliberately no
local branch, no "if the emulator is on this host" shortcut, and no `adb` invocation
against anything but a serial that lives inside the VM. The APK crosses the wire; it
does not open here.

Two operational facts from the runbook are encoded rather than remembered:

* **Retry every scripted `gcloud` call.** Calls to `*.googleapis.com` fail
  intermittently from some networks (`SSL: WRONG_VERSION_NUMBER`), and one failed call
  must not abort a job that is otherwise fine.
* **The VM is stopped when not detonating.** `instance_state()` reports that rather
  than starting it: an idle nested-virt VM is the fastest way to consume the budget, so
  starting one is an operator's decision (`make lab-up`), never a side effect of a job.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from drishti.config import Settings
from drishti.contracts.dynamic_trace import ObservationArtifact
from drishti.contracts.frontier import Morph
from drishti.logging import get_logger

log = get_logger(__name__)

#: How many times a `gcloud` call is retried before the step is considered failed.
MAX_GCLOUD_ATTEMPTS = 4

#: Seconds to wait between retries, multiplied by the attempt number.
RETRY_BACKOFF_S = 5

#: Where `detonator_deploy.sh` puts the VM-side tree. Mirrored from the runbook.
DETONATOR_ROOT = "/opt/drishti"

#: `dynamic_analyze.py` exits 2 when the run completed but its artifact is not
#: `safe_for_ingestion`. The detonation happened; the artifact is the verdict on it.
RC_UNSAFE_ARTIFACT = 2

#: The emulator serial inside the VM. One AVD, one serial (`detonator_run.sh`).
EMULATOR_SERIAL = "emulator-5554"

#: Frida morph scripts, laptop-side. The VM has the same tree under `lib/`, so the set
#: of applicable kinds can be checked before a round trip that would fail with rc 5.
MORPH_SCRIPT_DIR = Path(__file__).resolve().parent / "scripts" / "morph"


class DetonatorUnreachableError(RuntimeError):
    """The detonator could not be driven. Never downgraded to an empty trace."""


class DetonatorClient(Protocol):
    """What `LiveSandboxSource` needs from a detonator, real or fake."""

    def instance_state(self) -> str: ...

    def stage(self, apk_path: Path, sha256: str) -> None: ...

    def detonate(self, sha256: str, *, morphs: tuple[Morph, ...], duration_s: int) -> None: ...

    def collect(self, sha256: str, *, morphed: bool = False) -> ObservationArtifact: ...


@dataclass(frozen=True)
class DetonatorTarget:
    """Which VM to drive. Resolved from settings so nothing is hardcoded at a call site."""

    project: str
    zone: str
    instance: str
    duration_s: int = 120

    @classmethod
    def from_settings(cls, settings: Settings) -> DetonatorTarget | None:
        """Return the target, or None when the lab is not configured at all."""
        if not settings.gcp_project:
            return None
        return cls(
            project=settings.gcp_project,
            zone=settings.gcp_zone,
            instance=settings.gcp_detonator_instance,
            duration_s=settings.sandbox_duration_s,
        )


def _run(
    args: list[str], *, timeout: int, ok_returncodes: frozenset[int] = frozenset({0})
) -> subprocess.CompletedProcess[str]:
    """One bounded `gcloud` call, retried only on transport-shaped failures.

    `ok_returncodes` exists because `gcloud compute ssh` propagates the *remote*
    command's exit status, so a non-zero code can mean "the remote work happened and
    reported something" rather than "the call did not get there". Conflating the two
    turns a completed detonation into an unreachable detonator — see `detonate`.
    """
    last: Exception | None = None
    for attempt in range(1, MAX_GCLOUD_ATTEMPTS + 1):
        try:
            # Fixed argv, no shell: nothing here interpolates into a command line.
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            last = exc
        else:
            if result.returncode in ok_returncodes:
                return result
            # The TAIL, not the head. Every IAP call opens stderr with a ~200-character
            # "consider installing NumPy" banner, so `[:400]` reliably kept the
            # boilerplate and threw the reason away — two failed detonations in a row
            # both logged `DetonatorUnreachableError: WARNING:` while the real message
            # ("another detonation is already running") never surfaced.
            last = DetonatorUnreachableError(result.stderr.strip()[-400:] or "gcloud failed")
            # A non-zero exit that is not transport-shaped will not fix itself.
            if "SSL" not in result.stderr and "timed out" not in result.stderr.lower():
                raise last
        if attempt < MAX_GCLOUD_ATTEMPTS:
            log.warning("gcloud_retrying", attempt=attempt, command=args[1] if args else "?")
            time.sleep(RETRY_BACKOFF_S * attempt)
    raise DetonatorUnreachableError(f"gcloud failed after {MAX_GCLOUD_ATTEMPTS} attempts: {last}")


@dataclass
class RemoteDetonatorClient:
    """The real client. Every call is a remote command over the IAP tunnel."""

    target: DetonatorTarget | None = None

    def _require_target(self) -> DetonatorTarget:
        if self.target is None:
            raise DetonatorUnreachableError(
                "no detonator configured: set DRISHTI_GCP_PROJECT (see .env.example). "
                "Without a lab there is nowhere a sample may legally be executed."
            )
        return self.target

    def _ssh(
        self,
        command: str,
        *,
        timeout: int = 300,
        ok_returncodes: frozenset[int] = frozenset({0}),
    ) -> str:
        target = self._require_target()
        return _run(
            [
                "gcloud",
                "compute",
                "ssh",
                target.instance,
                f"--zone={target.zone}",
                f"--project={target.project}",
                "--tunnel-through-iap",
                f"--command={command}",
            ],
            timeout=timeout,
            ok_returncodes=ok_returncodes,
        ).stdout

    def instance_state(self) -> str:
        """`RUNNING`, `TERMINATED`, or `UNKNOWN`. Never starts the VM as a side effect."""
        target = self.target
        if target is None:
            return "UNCONFIGURED"
        try:
            out = _run(
                [
                    "gcloud",
                    "compute",
                    "instances",
                    "describe",
                    target.instance,
                    f"--zone={target.zone}",
                    f"--project={target.project}",
                    "--format=value(status)",
                ],
                timeout=60,
            ).stdout.strip()
        except (DetonatorUnreachableError, OSError) as exc:
            log.info("detonator_state_unknown", error=str(exc)[:200])
            return "UNKNOWN"
        return out or "UNKNOWN"

    def stage(self, apk_path: Path, sha256: str) -> None:
        """Copy one APK into the VM's ephemeral scratch. It is never opened here."""
        target = self._require_target()
        _run(
            [
                "gcloud",
                "compute",
                "scp",
                str(apk_path),
                f"{target.instance}:{DETONATOR_ROOT}/scratch/{sha256}.apk",
                f"--zone={target.zone}",
                f"--project={target.project}",
                "--tunnel-through-iap",
            ],
            timeout=900,
        )
        log.info("sample_staged", sha256=sha256[:12], instance=target.instance)

    def detonate(self, sha256: str, *, morphs: tuple[Morph, ...], duration_s: int) -> None:
        """Run the harness on the VM. Containment is re-verified there, per sample.

        Two subcommands, not one, because pass 2 is a genuinely different run:
        `detonate <sha> [duration]` writes `results/<sha>.json`, while
        `morph <sha> <kinds> [duration]` requires a pass-1 artifact to exist and writes
        `results/<sha>.morph.json`. The loop's claim is a *difference*, and the VM
        refuses pass 2 outright if there is nothing to difference against.

        Everything interpolated here goes through `shlex.quote`. That matters more than
        usual on this path: `kinds` is derived from a model-authored morph plan, and
        CLAUDE.md rule 7 is that LLM output reaching a command surface is validated, not
        concatenated.
        """
        self._require_target()
        base = f"{DETONATOR_ROOT}/bin/detonator_run.sh"
        if not morphs:
            command = f"{base} detonate {shlex.quote(sha256)} {int(duration_s)}"
        else:
            kinds = self._runnable_kinds(morphs)
            command = (
                f"{base} morph {shlex.quote(sha256)} "
                f"{shlex.quote(','.join(kinds))} {int(duration_s)}"
            )
        # rc 2 is `dynamic_analyze.py` saying "the run happened and the artifact is not
        # safe to ingest" — not "the detonator is unreachable". Raising here would skip
        # `collect()` entirely, so `LiveSandboxSource.run`'s gate could never name the
        # real reason (`outcome=failed`, a dirty snapshot, unverified containment) and
        # the pipeline would fall back to a synthetic stub that contradicts a signed
        # containment manifest. Let it return; only the artifact can judge the run.
        self._ssh(
            command, timeout=duration_s + 600, ok_returncodes=frozenset({0, RC_UNSAFE_ARTIFACT})
        )
        log.info("detonation_finished", sha256=sha256[:12], morphs=len(morphs))

    @staticmethod
    def _runnable_kinds(morphs: tuple[Morph, ...]) -> list[str]:
        """Distinct morph kinds that actually have a Frida script to apply.

        `MorphKind` enumerates nine kinds; five have scripts. The VM refuses an unknown
        kind with rc 5 rather than running an unmorphed pass 2 and reporting it as
        morphed — a pass 2 that applied nothing is not a negative result. Checking here
        turns that into a legible error instead of an opaque exit code, and refuses
        rather than silently dropping the unsupported ones.
        """
        available = {p.stem for p in MORPH_SCRIPT_DIR.glob("*.js")}
        wanted = list(dict.fromkeys(m.kind.value for m in morphs))
        missing = [k for k in wanted if k not in available]
        runnable = [k for k in wanted if k in available]
        if missing:
            raise DetonatorUnreachableError(
                f"no morph script for {', '.join(missing)}; "
                f"available kinds are {', '.join(sorted(available))}"
            )
        if not runnable:
            raise DetonatorUnreachableError("the morph plan contains nothing that can be applied")
        return runnable

    def collect(self, sha256: str, *, morphed: bool = False) -> ObservationArtifact:
        """Read the run's artifact back out with the VM still sealed.

        `detonator_collect.sh` publishes a whole batch to GCS; a single job only needs
        the one file, and reading it over the existing tunnel keeps the VM sealed rather
        than opening egress for one `gsutil cp`.
        """
        name = f"{sha256}.morph.json" if morphed else f"{sha256}.json"
        # `sudo`, because `detonator_run.sh` runs the harness under `as_root` and the
        # artifact lands root:root 0600. `detonator_collect.sh` chowns the whole results
        # directory before its batch read; this path reads one file and must elevate for
        # itself, or a detonation that fully succeeded is lost at the last step.
        raw = self._ssh(f"sudo cat {DETONATOR_ROOT}/results/{shlex.quote(name)}", timeout=120)
        if not raw.strip():
            raise DetonatorUnreachableError(f"no artifact was produced for {sha256[:12]}")
        # Strict validation on purpose: a malformed artifact off the VM fails loudly
        # rather than being massaged into something plausible.
        return ObservationArtifact.model_validate_json(raw)
