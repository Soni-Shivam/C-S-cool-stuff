"""Repository-level safety invariants.

These are contract tests because they guard a *boundary*, not a behaviour: the
boundary between "this repo analyses malware" and "this repo distributes it".
They run in CI on every push from the first commit onward.

00_GUIDING_MAP.md §4 requires `*.apk` gitignored from commit #1 with an explicit
allowlist for `canary/`. v1 never had that rule, which is exactly why it needs a
test rather than a good intention.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Extensions that must never be tracked outside canary/.
#: - samples and payloads: apk/apks/xapk/dex
#: - trained models: joblib/pkl — data, not code, and v1 shipped a *synthetic*
#:   model reported as real (docs/CARRIED_FINDINGS.md H7)
#: - key material: pem/p12/jks
FORBIDDEN_SUFFIXES = {
    ".apk",
    ".apks",
    ".xapk",
    ".dex",
    ".joblib",
    ".pkl",
    ".pem",
    ".p12",
    ".jks",
}

ALLOWLIST_PREFIXES = ("canary/",)


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _tracked_files() -> list[str]:
    return [line for line in _git("ls-files").splitlines() if line]


def _is_ignored(path: str) -> bool:
    """True if `path` would actually be ignored by git.

    `git check-ignore -q` is NOT usable for this. Its exit status is 0 when *any*
    pattern matches — and a negation (`!canary/dist/*.apk`) is a matching pattern —
    so an allowlisted file reports exit 0 exactly like a blocked one. Asserting on
    the exit code silently inverts the meaning of every allowlist test.

    `-v` prints `<source>:<line>:<pattern>\\t<path>` for the winning rule, so the
    authoritative answer is whether that pattern is a negation.
    """
    result = subprocess.run(
        ["git", "check-ignore", "-v", "--no-index", path],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return False  # no pattern matched at all
    _source, _line, pattern = result.stdout.strip().split("\t")[0].split(":", 2)
    return not pattern.startswith("!")


def test_no_forbidden_artifacts_tracked() -> None:
    """No sample, model binary, or private key is committed."""
    offenders = [
        path
        for path in _tracked_files()
        if Path(path).suffix.lower() in FORBIDDEN_SUFFIXES
        and not path.startswith(ALLOWLIST_PREFIXES)
    ]
    assert offenders == [], (
        "Forbidden artifacts are tracked in git. Samples, trained models and key "
        f"material must never be committed: {offenders}"
    )


def test_no_env_file_tracked() -> None:
    """No .env is committed. v1's held live keys that had to be rotated."""
    offenders = [p for p in _tracked_files() if Path(p).name == ".env"]
    assert offenders == [], f".env files must never be committed: {offenders}"


@pytest.mark.parametrize(
    "candidate",
    [
        "data/samples/evil.apk",
        "some/nested/dir/payload.apk",
        "dropped.dex",
        "models/classifier.joblib",
        "secrets/ledger.pem",
        ".env",
        "backend/.env",
    ],
)
def test_gitignore_actually_ignores_dangerous_paths(candidate: str) -> None:
    """The .gitignore rules work, not just look right.

    `git check-ignore` is the authority here — reading the file and reasoning about
    pattern semantics is how you convince yourself of a rule that does not hold.
    """
    assert _is_ignored(candidate), (
        f"{candidate!r} is NOT gitignored. 00_GUIDING_MAP.md §4 requires samples, "
        "keys and model binaries to be unstageable by accident."
    )


def test_canary_apk_is_allowlisted() -> None:
    """The one APK we author ourselves must remain committable.

    The allowlist is what makes the blanket `*.apk` rule usable; if this breaks,
    the canary silently stops being version-controlled and the demo starts
    depending on a Java toolchain being present.

    The path matters. git cannot re-include a file whose parent directory is
    excluded, so a `!` rule pointing inside `canary/app/build/` (Gradle's output,
    correctly ignored) can never fire. The committed artifact therefore lives at
    `canary/dist/`. This test is what caught that.
    """
    assert not _is_ignored("canary/dist/canary.apk"), (
        "canary/dist/*.apk must NOT be ignored — 00_GUIDING_MAP.md §4 allowlists the "
        "canary. Check that no parent-directory rule (build/, dist/) shadows it."
    )


def test_gradle_build_output_is_still_ignored() -> None:
    """Allowlisting the canary must not accidentally un-ignore Gradle output."""
    assert _is_ignored("canary/app/build/outputs/apk/debug/canary.apk"), (
        "Gradle build output must stay ignored; only canary/dist/ is committed."
    )


def test_models_gitkeep_survives() -> None:
    """`models/` holds gitignored binaries but must keep its .gitkeep.

    Same parent-directory trap as the canary: `models/` as a directory pattern
    would make `!models/.gitkeep` dead, so the rule must be `models/*`.
    """
    assert not _is_ignored("models/.gitkeep"), (
        "models/.gitkeep must NOT be ignored, or the directory vanishes from clones. "
        "Use `models/*` rather than `models/`."
    )


def test_v1_reference_is_not_importable_from_drishti() -> None:
    """Nothing in the v2 package imports the frozen v1 tree.

    v1-reference/ is a historical copy. An import crossing that boundary means v2
    is quietly depending on code nobody maintains or tests (v1-reference/README.md).
    """
    offenders: list[str] = []
    for path in (REPO_ROOT / "drishti").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "v1_reference" in text or "v1-reference" in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == [], f"v2 code must not reference v1-reference/: {offenders}"
