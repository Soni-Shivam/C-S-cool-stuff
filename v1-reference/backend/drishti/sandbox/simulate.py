"""M3 dynamic interrogation — SIMULATED.

DRISHTI's design calls for a hardened sandbox with adversarial elicitation
(Generative C2 emulation, JIT sandbox synthesis). Detonating live malware is
unsafe and out of scope for the prototype, so this module implements the real
*interface* and a synthetic behaviour generator: it derives plausible runtime
observations from the static hypotheses and labels every one as SIMULATED. It
NEVER executes the APK. The paper and UI both present these as designed-and-
simulated, not live results."""
from typing import Literal

from pydantic import BaseModel, Field

# Map a static permission-combo to the runtime behaviour it would plausibly cause.
_COMBO_BEHAVIOUR = {
    "otp_interception": "registered an SMS_RECEIVED broadcast receiver and forwarded an "
                        "incoming OTP to a synthetic C2 endpoint",
    "accessibility_abuse": "enabled its accessibility service and read/auto-clicked UI "
                           "elements of a foreground app",
    "overlay_attack": "drew a full-screen overlay over a foreground (banking-like) activity",
    "banker_overlay_accessibility": "combined an overlay with accessibility auto-input to "
                                    "harvest credentials from a decoy banking screen",
    "device_admin_persistence": "requested device-admin activation to resist uninstall",
    "dropper_install": "attempted to fetch and install a secondary package",
    "sms_send_fraud": "sent outbound SMS to a premium/short-code number",
    "contacts_exfil": "read the contact list and staged it for exfiltration",
}


class DynamicResult(BaseModel):
    observations: list[str] = Field(default_factory=list)
    b_dynamic: float = 0.0
    simulated: bool = True
    status: Literal["absent", "simulated", "observed"] = "simulated"
    mitre_observed: list[str] = Field(default_factory=list)


def interrogate(static_result, ml_result, led, timestamp: str) -> DynamicResult:
    observations: list[str] = []
    severities: list[float] = []
    for combo in static_result.combos:
        behaviour = _COMBO_BEHAVIOUR.get(combo["id"])
        if not behaviour:
            continue
        obs = f"[SIMULATED] The app {behaviour}."
        observations.append(obs)
        severities.append(float(combo["severity"]))
        led.append(
            "dynamic_obs", "sandbox_sim", obs,
            location="simulated-run", confidence=float(combo["severity"]), timestamp=timestamp,
        )

    b_dynamic = max(severities, default=0.0)
    if not observations:
        led.append(
            "dynamic_obs", "sandbox_sim",
            "[SIMULATED] No high-risk runtime behaviour derived from static hypotheses.",
            location="simulated-run", confidence=0.2, timestamp=timestamp,
        )
    return DynamicResult(observations=observations, b_dynamic=round(b_dynamic, 3), simulated=True)


def absent_result() -> DynamicResult:
    """Represent a deliberate lack of independently produced dynamic evidence."""
    return DynamicResult(observations=[], b_dynamic=0.0, simulated=False, status="absent")
