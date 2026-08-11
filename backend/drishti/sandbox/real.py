"""Ingest REAL dynamic-analysis output from the sealed detonation VM.

`scripts/dynamic_analyze.py` runs on the isolated GCE detonator (the only place a sample
is ever executed) and emits observations.json. This module turns that JSON into evidence
nodes and a measured behavioural risk `B`, replacing the simulated behaviour generator.

Nothing here executes anything — it only reads a JSON artefact.
"""
import json
from pathlib import Path

from drishti.sandbox.observation import ObservationArtifact
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
    artifact = ObservationArtifact.model_validate_json(json.dumps(payload))
    if expected_sha256 is not None and artifact.sha256 != expected_sha256.lower():
        raise ValueError("observations artifact SHA-256 does not match the analyzed APK")
    if not artifact.safe_for_ingestion:
        raise ValueError("observations artifact failed containment, snapshot, or execution acceptance gates")
    raw = artifact.observations
    observations: list[str] = []
    severities: list[float] = []

    for obs in raw:
        technique = obs.technique
        mitre = obs.mitre
        detail = obs.detail[:300]
        observations.append(
            f"[OBSERVED] {technique}" + (f" ({mitre})" if mitre else "")
            + (f": {detail}" if detail else "")
        )
        severities.append(_TECHNIQUE_SEVERITY.get(mitre, 0.5))

    mitre_observed = artifact.mitre_observed

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
    artifact = ObservationArtifact.model_validate_json(json.dumps(payload))
    result = result_from_payload(artifact.model_dump(mode="json"), expected_sha256=expected_sha256)

    if not result.observations:
        led.append("dynamic_obs", "sandbox_real",
                   "[OBSERVED] Bounded detonation completed with no captured behavioural events; result is inconclusive, not benign.",
                   location=f"detonation:{artifact.package}",
                   confidence=0.3, timestamp=timestamp)
        return result

    for obs, sev in zip(result.observations,
                        [_TECHNIQUE_SEVERITY.get(o.mitre, 0.5)
                         for o in artifact.observations]):
        led.append("dynamic_obs", "sandbox_real", obs,
                   location=f"detonation:{artifact.package}",
                   confidence=sev, timestamp=timestamp)
    return result
