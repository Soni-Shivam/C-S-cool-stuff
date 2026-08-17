"""Static facts converted into bounded dynamic-analysis hypotheses."""

from __future__ import annotations

from drishti.contracts.static_report import Hypothesis, HypothesisKind, PermissionCombo
from drishti.util import new_id

_TARGET_PACKAGES = frozenset({"com.sbi.yono", "com.phonepe.app", "net.one97.paytm"})


def derive_hypotheses(
    *,
    sink_hits: set[str],
    permission_combos: tuple[PermissionCombo, ...],
    package_strings: tuple[str, ...],
    urls: tuple[str, ...],
    dcl_indicators: tuple[str, ...],
    evidence_refs: tuple[str, ...],
) -> tuple[Hypothesis, ...]:
    """Derive at most eight evidence-cited hypotheses without an LLM or I/O."""
    kinds = {combo.rule_id for combo in permission_combos}
    output: list[Hypothesis] = []
    if "pkg_query" in sink_hits:
        candidates = sorted(set(package_strings).intersection(_TARGET_PACKAGES))
        if candidates:
            output.append(
                Hypothesis(
                    id=new_id("hyp"),
                    kind=HypothesisKind.TARGET_APP_PROBE,
                    statement="Queries PackageManager for target banking or wallet applications.",
                    target_apis=("android.content.pm.PackageManager.getPackageInfo",),
                    suggested_probe={"morph": "install_packages", "candidates": candidates},
                    priority=1,
                    evidence_refs=evidence_refs,
                )
            )
    if dcl_indicators or "dex_load" in sink_hits:
        output.append(
            Hypothesis(
                id=new_id("hyp"),
                kind=HypothesisKind.SECONDARY_PAYLOAD,
                statement="Dynamic code-loading indicators require payload collection.",
                target_apis=("dalvik.system.DexClassLoader.$init", "javax.crypto.Cipher.doFinal"),
                suggested_probe={"hook": "cipher_dump"},
                priority=1,
                evidence_refs=evidence_refs,
            )
        )
    if "OTP_THEFT_SURFACE" in kinds and "network" in sink_hits:
        output.append(
            Hypothesis(
                id=new_id("hyp"),
                kind=HypothesisKind.OTP_EXFIL,
                statement="SMS access and network capability may support OTP exfiltration.",
                target_apis=("android.telephony.SmsMessage.getMessageBody",),
                priority=2,
                evidence_refs=evidence_refs,
            )
        )
    if "OVERLAY_CREDENTIAL_THEFT" in kinds or "overlay" in sink_hits:
        output.append(
            Hypothesis(
                id=new_id("hyp"),
                kind=HypothesisKind.OVERLAY_ATTACK,
                statement="Overlay capability may support credential interception.",
                target_apis=("android.view.WindowManager.addView",),
                priority=2,
                evidence_refs=evidence_refs,
            )
        )
    if "ACCESSIBILITY_ABUSE" in kinds:
        output.append(
            Hypothesis(
                id=new_id("hyp"),
                kind=HypothesisKind.ACCESSIBILITY_ABUSE,
                statement="Accessibility service declarations require runtime observation.",
                target_apis=(
                    "android.accessibilityservice.AccessibilityService.onAccessibilityEvent",
                ),
                priority=1,
                evidence_refs=evidence_refs,
            )
        )
    if urls and "network" in sink_hits:
        output.append(
            Hypothesis(
                id=new_id("hyp"),
                kind=HypothesisKind.C2_BEACON,
                statement="Network sink and embedded endpoints suggest a beaconing path.",
                suggested_probe={"generative_c2": True},
                priority=3,
                evidence_refs=evidence_refs,
            )
        )
    return tuple(sorted(output, key=lambda item: item.priority)[:8])
