#!/usr/bin/env python3
"""CLI for one admitted detonation on the sealed runtime.

Pass 2 of the adversarial loop runs through the same entrypoint as pass 1, with
`--morph-script` supplying the Frida code that answers whatever the sample asked for.
The morph JS is *prepended* to the base hooks and the pair is loaded as one script,
because `collect_frida` creates exactly one script from one file — so the composition
happens here rather than in the harness, and the harness stays a thing that detonates.

Two rules govern that composition and neither is negotiable:

* **A morph changes what the sample observes. It never adds capability to the sample.**
  That is the whole safety rationale for answering a live sample at all (CLAUDE.md,
  "Hard boundaries").
* **A morphed run says so in its own artifact.** `--morph-label` writes the applied
  morph kinds into `diagnostics`, so a pass-2 trace cannot be mistaken for a pass-1
  one by anything downstream — including by a human reading the JSON. Presenting a
  morphed trace as an unmorphed one would be the same class of dishonesty as
  presenting a replay as live.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import tempfile
from pathlib import Path

from drishti.contracts.dynamic_trace import ObservationArtifact
from drishti.m3_dynamic.harness import DEFAULT_HOOKS, DynamicHarness, HarnessConfig


def compose_hooks(base: Path, morph_scripts: list[Path], workdir: Path) -> Path:
    """One JS file: every morph, then the base hooks.

    Morphs go first so their Java replacements are installed before an observation hook
    can call the method it replaced. Each fragment is fenced by a comment naming its
    source file, because a stack trace out of a 900-line concatenation is otherwise
    unattributable.
    """
    if not morph_scripts:
        return base
    parts = []
    for script in morph_scripts:
        parts.append(f"// ==== morph: {script.name} ====\n{script.read_text(encoding='utf-8')}")
    parts.append(f"// ==== base hooks: {base.name} ====\n{base.read_text(encoding='utf-8')}")
    composed = workdir / "composed_hooks.js"
    composed.write_text("\n\n".join(parts), encoding="utf-8")
    return composed


def annotate(output: Path, labels: list[str], pass_num: int) -> None:
    """Record the morph pass in the artifact's own diagnostics, then re-validate.

    Round-tripping through `ObservationArtifact` is deliberate: if this edit ever
    produced something the contract rejects, the run should fail loudly here rather
    than leave a malformed artifact for `detonator_collect.sh` to refuse later.
    """
    data = json.loads(output.read_text())
    note = f"pass={pass_num}; morphs={','.join(labels) if labels else 'none'}"
    data["diagnostics"] = [*(data.get("diagnostics") or []), note]
    output.write_text(ObservationArtifact.model_validate(data).model_dump_json(indent=2))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--duration", type=int, default=120, choices=range(1, 1801))
    parser.add_argument(
        "--sample-kind",
        choices=("inert_fixture", "benign", "vetted_malware"),
        default="inert_fixture",
    )
    parser.add_argument("--hooks", type=Path, default=DEFAULT_HOOKS)
    parser.add_argument(
        "--morph-script",
        type=Path,
        action="append",
        default=[],
        help="Frida JS prepended to the base hooks. Repeatable.",
    )
    parser.add_argument(
        "--morph-label",
        action="append",
        default=[],
        help="morph kind recorded in the artifact's diagnostics. Repeatable.",
    )
    parser.add_argument("--pass-num", type=int, default=1, choices=(1, 2))
    args = parser.parse_args()
    if not args.apk.is_file():
        raise SystemExit("APK path is not a regular file")
    for script in args.morph_script:
        if not script.is_file():
            raise SystemExit(f"morph script is not a regular file: {script}")
    # A morphed run that does not declare its morphs is the artifact this whole CLI
    # exists to prevent, so refuse it rather than emit an undeclared pass-2 trace.
    if args.morph_script and not args.morph_label:
        raise SystemExit("--morph-script requires at least one --morph-label")

    lock_path = Path("/run/drishti-analysis.lock")
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SystemExit("another detonation is already running") from exc
        with tempfile.TemporaryDirectory(prefix="drishti-hooks-") as tmp:
            hooks = compose_hooks(args.hooks, args.morph_script, Path(tmp))
            artifact = DynamicHarness(
                HarnessConfig(
                    apk=args.apk,
                    output=args.out,
                    duration_s=args.duration,
                    sample_kind=args.sample_kind,
                    hooks=hooks,
                )
            ).run()
    annotate(args.out, args.morph_label, args.pass_num)
    print(
        f"artifact={args.out} sha256={artifact.sha256} "
        f"outcome={artifact.outcome} observations={len(artifact.observations)} "
        f"pass={args.pass_num} morphs={','.join(args.morph_label) or 'none'}"
    )
    return 0 if artifact.safe_for_ingestion else 2


if __name__ == "__main__":
    raise SystemExit(main())
