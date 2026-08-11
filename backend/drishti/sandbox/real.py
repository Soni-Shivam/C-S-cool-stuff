"""Ingest REAL dynamic-analysis output from the sealed detonation VM.

`scripts/dynamic_analyze.py` runs on the isolated GCE detonator (the only place a sample
is ever executed) and emits observations.json. This module turns that JSON into evidence
nodes and a measured behavioural risk `B`, replacing the simulated behaviour generator.

Nothing here executes anything — it only reads a JSON artefact.
"""
import json
from pathlib import Path

from drishti.sandbox.simulate import DynamicResult

# Observed-behaviour severity by MITRE technique. A *real* observation is stronger
# evidence than a static capability, so these sit higher than the static combo weights.
_TECHNIQUE_SEVERITY = {
    "T1582": 0.95,      # SMS control — OTP interception / premium fraud
    "T1417": 0.95,      # input capture (accessibility screen-read)
    "T1516": 0.92,      # input injection (automated clicks)
    "T1521": 0.85,      # encrypted channel / custom crypto exfil
    "T1407": 0.85,      # download new code (dropper)
    "T1626": 0.80,      # abuse elevation (device admin persistence)
    "T1641.001": 0.80,  # clipboard crypto-address swap
    "T1437": 0.60,      # app-layer C2 protocol
    "T1409": 0.60,      # access app data
    "T1414": 0.55,      # clipboard read
    "T1426": 0.40,      # device fingerprinting
    "T1422": 0.35,      # network fingerprinting
}


def result_from_payload(payload: dict, *, expected_sha256: str | None = None) -> DynamicResult:
    artifact_sha256 = str(payload.get("sha256", "")).lower()
    if expected_sha256 is not None and artifact_sha256 != expected_sha256.lower():
        raise ValueError("observations artifact SHA-256 does not match the analyzed APK")
    raw = payload.get("observations", []) or []
    observations: list[str] = []
    severities: list[float] = []

    for obs in raw:
        technique = str(obs.get("technique", "observed behaviour"))
        mitre = str(obs.get("mitre", "") or "")
        detail = str(obs.get("detail", "") or "")[:300]
        observations.append(
            f"[OBSERVED] {technique}" + (f" ({mitre})" if mitre else "")
            + (f": {detail}" if detail else "")
        )
        severities.append(_TECHNIQUE_SEVERITY.get(mitre, 0.5))

    mitre_observed = payload.get("mitre_observed") or sorted(
        {str(o.get("mitre")) for o in raw if o.get("mitre")})

    # Highest-severity observed behaviour drives B; a second corroborating behaviour
    # nudges it up slightly, but B is capped at 1.0.
    top = max(severities, default=0.0)
    corroboration = 0.05 * max(0, len({s for s in severities}) - 1)
    return DynamicResult(
        observations=observations,
        b_dynamic=round(min(1.0, top + corroboration), 3),
        simulated=False,
        status="observed",
        mitre_observed=list(mitre_observed),
    )


def load_real_observations(path: str | Path, *, expected_sha256: str | None = None) -> DynamicResult:
    return result_from_payload(
        json.loads(Path(path).read_text()), expected_sha256=expected_sha256
    )


def ingest_real(payload_or_path, led, timestamp: str, *, expected_sha256: str | None = None) -> DynamicResult:
    """Build a DynamicResult from real detonation output and append its evidence nodes."""
    if isinstance(payload_or_path, (str, Path)):
        payload = json.loads(Path(payload_or_path).read_text())
    else:
        payload = payload_or_path
    result = result_from_payload(payload, expected_sha256=expected_sha256)

    if not result.observations:
        led.append("dynamic_obs", "sandbox_real",
                   "[OBSERVED] Sample executed; no high-risk runtime behaviour captured.",
                   location=f"detonation:{payload.get('package', 'unknown')}",
                   confidence=0.3, timestamp=timestamp)
        return result

    for obs, sev in zip(result.observations,
                        [_TECHNIQUE_SEVERITY.get(o.get("mitre", ""), 0.5)
                         for o in payload.get("observations", [])]):
        led.append("dynamic_obs", "sandbox_real", obs,
                   location=f"detonation:{payload.get('package', 'unknown')}",
                   confidence=sev, timestamp=timestamp)
    return result
