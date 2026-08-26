"""Telling a banking trojan apart from an app that is legitimately privileged.

**The problem this exists to solve.** Truecaller reads SMS, reads the call log, queries
installed packages and draws overlays. So does an overlay banking trojan. Their
*permission sets are the same*, and half of India has Truecaller installed. Any detector
keyed on permissions flags both, and a product that flags Truecaller is dead on arrival.

The permission is the capability. It is not the intent. What separates the two is
**target specificity and data destination**, and both are visible statically:

* Truecaller draws over the **dialer**. A banking trojan enumerates installed packages,
  checks them against a hardcoded roster of banks, and draws over **whichever bank you
  actually have**. Truecaller does not ship a list of fifty Indian bank package names.
* Truecaller's SMS access reaches a **local** spam classifier. A trojan's SMS access and
  its **network** sink hang off the same entrypoint — the message is read in order to be
  sent somewhere.
* Truecaller keeps its launcher icon. A trojan disables it after first run.
* Truecaller is signed by a certificate years old and stable across versions. A fraud
  APK is signed by one generated last week.

So this module never asks "does it have READ_SMS". It asks what the app does with it.

**It never returns "benign".** The best verdict available is `INDETERMINATE`, matching
the rule elsewhere in this codebase that absence of evidence is not evidence of
innocence. A trusted publisher yields `LEGITIMATE_PRIVILEGED`, which is a statement
about the *signer*, not a clean bill of health for the code.
"""

from __future__ import annotations

from pathlib import Path

from drishti.contracts.static_report import (
    BenignLookalikeVerdict,
    LookalikeAssessment,
    LookalikeSignal,
    StaticReport,
)

_KB = Path(__file__).resolve().parents[2] / "data" / "kb"

#: Permissions that a legitimate caller-ID, SMS-backup or anti-spam app genuinely needs.
#: Holding these is NOT a finding. They are listed so the report can say out loud which
#: capabilities the sample shares with software the user already trusts.
DUAL_USE_PERMISSIONS = (
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.QUERY_ALL_PACKAGES",
)

#: Lexicon that indicates the app cares about one-time passwords specifically, rather
#: than about messages in general. A spam classifier does not need these.
_OTP_LEXICON = (
    "otp",
    "one time password",
    "one-time password",
    "verification code",
    "vpa",
    "upi id",
    "mpin",
    "cvv",
    "card number",
    "net banking",
    "netbanking",
)

#: Constants an app touches when it hides its own launcher entry.
_ICON_HIDING = (
    "setcomponentenabledsetting",
    "component_enabled_state_disabled",
)

#: Accessibility APIs used to click through consent dialogs on the user's behalf.
_ACCESSIBILITY_ABUSE = (
    "performglobalaction",
    "action_accessibility_focus",
    "performaction",
    "gesture_description",
)

_SMS_READ_SINKS = frozenset({"sms_body", "sms_query"})
_NETWORK_SINKS = frozenset({"network", "network_socket", "network_okhttp"})
_PKG_ENUM_SINKS = frozenset({"pkg_list", "pkg_query", "pkg_resolve"})
_CODE_LOAD_SINKS = frozenset({"dex_load", "dex_load_path", "native_load"})

#: A certificate younger than this, from an unknown signer, is a weak but real signal.
#: Legitimate publishers reuse a signing key for years — Android requires it, because a
#: key change breaks the upgrade path.
_FRESH_CERT_DAYS = 60

#: At or above this weighted score the shape is a trojan's, not a privileged app's.
TROJAN_SHAPE_THRESHOLD = 0.50


def _load_list(name: str) -> frozenset[str]:
    """Read a knowledge-base list, ignoring comments and blanks."""
    path = _KB / name
    if not path.exists():
        return frozenset()
    return frozenset(
        line.strip().lower()
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    )


def _reachable_sinks(report: StaticReport) -> set[str]:
    """Sink ids reachable from an app entrypoint.

    Lifecycle-reachable only. Dead library code reaches dangerous sinks constantly, and
    counting it is how a detector acquires a false-positive rate it cannot explain.
    """
    return {p.sink_id for p in report.call_paths if p.reachable_from_lifecycle}


def _entrypoints_reaching(report: StaticReport, sinks: frozenset[str]) -> set[str]:
    return {
        p.entrypoint for p in report.call_paths if p.reachable_from_lifecycle and p.sink_id in sinks
    }


def assess(report: StaticReport) -> LookalikeAssessment:
    """Decide whether a privileged app looks like a trojan or like a legitimate tool."""
    haystack = " ".join(
        (*report.urls, *report.crypto_constants, *report.sink_hits, *report.dcl_indicators)
    ).lower()
    # Package-shaped strings are where a target roster would live.
    package_blob = " ".join(report.sink_hits).lower()

    financial = _load_list("financial_packages.txt")
    trusted_publishers = _load_list("known_good_publishers.txt")

    reachable = _reachable_sinks(report)
    signals: list[LookalikeSignal] = []

    def add(sid: str, present: bool, weight: float, detail: str) -> None:
        signals.append(LookalikeSignal(id=sid, present=present, weight=weight, detail=detail))

    # ── 1. does it carry a roster of banks to impersonate? ───────────────────
    # The strongest single discriminator. Searched across every extracted string, not
    # just package-shaped ones, because the roster is sometimes assembled at runtime.
    targeted = sorted(pkg for pkg in financial if pkg in haystack or pkg in package_blob)
    add(
        "financial_app_roster",
        bool(targeted),
        0.30,
        (
            f"references {len(targeted)} known banking/UPI package(s): {', '.join(targeted[:6])}"
            if targeted
            else "no banking or UPI package identifiers found in extracted strings"
        ),
    )

    # ── 2. is SMS read on the same path that talks to the network? ───────────
    # Not dataflow — we do not claim taint. It is a structural proxy: one entrypoint
    # that reaches both a message-reading sink and a network sink. Truecaller's SMS
    # access reaches a local classifier; it does not share an entrypoint with a socket.
    sms_entry = _entrypoints_reaching(report, _SMS_READ_SINKS)
    net_entry = _entrypoints_reaching(report, _NETWORK_SINKS)
    shared = sorted(sms_entry & net_entry)
    add(
        "sms_and_network_share_entrypoint",
        bool(shared),
        0.25,
        (
            f"entrypoint(s) reach both a message-read sink and a network sink: "
            f"{', '.join(shared[:3])}"
            if shared
            else "no entrypoint reaches both a message-read sink and a network sink"
        ),
    )

    # ── 3. does it care about OTPs specifically? ─────────────────────────────
    otp_terms = sorted({t for t in _OTP_LEXICON if t in haystack})
    add(
        "otp_lexicon",
        bool(otp_terms),
        0.15,
        (
            f"strings reference credential/OTP concepts: {', '.join(otp_terms[:5])}"
            if otp_terms
            else "no OTP or credential lexicon in extracted strings"
        ),
    )

    # ── 4. overlay plus package enumeration ──────────────────────────────────
    # Drawing over the screen is fine. Drawing over the screen *after asking what is
    # installed* is the overlay-attack shape.
    overlay_targeted = "overlay" in reachable and bool(reachable & _PKG_ENUM_SINKS)
    add(
        "overlay_after_package_enumeration",
        overlay_targeted,
        0.20,
        (
            "reaches an overlay sink and a package-enumeration sink from a lifecycle "
            "entrypoint — the shape of choosing what to draw over"
            if overlay_targeted
            else "no overlay-plus-enumeration combination reachable"
        ),
    )

    # ── 5. does it hide its own icon? ────────────────────────────────────────
    hides = any(term in haystack for term in _ICON_HIDING)
    add(
        "launcher_icon_hiding",
        hides,
        0.20,
        (
            "references component-enabled-setting APIs used to disable a launcher entry"
            if hides
            else "no launcher-hiding APIs referenced"
        ),
    )

    # ── 6. accessibility used to act, not to assist ──────────────────────────
    a11y_abuse = "accessibility" in reachable and any(
        term in haystack for term in _ACCESSIBILITY_ABUSE
    )
    add(
        "accessibility_acts_on_the_user",
        a11y_abuse,
        0.20,
        (
            "accessibility service reachable and gesture/global-action APIs referenced "
            "— the shape of clicking consent dialogs on the user's behalf"
            if a11y_abuse
            else "no accessibility-automation combination found"
        ),
    )

    # ── 7. dropper capability ────────────────────────────────────────────────
    dropper = bool(reachable & _CODE_LOAD_SINKS) and (
        "android.permission.REQUEST_INSTALL_PACKAGES" in report.permissions
    )
    add(
        "second_stage_dropper",
        dropper,
        0.20,
        (
            "reaches a code-loading sink and declares REQUEST_INSTALL_PACKAGES"
            if dropper
            else "no reachable code-load plus install-packages combination"
        ),
    )

    # ── 8. who signed it ─────────────────────────────────────────────────────
    cert = report.certificate
    publisher_trusted = cert.sha256.lower() in trusted_publishers
    fresh_cert = not publisher_trusted and 0 <= cert.age_days < _FRESH_CERT_DAYS
    add(
        "freshly_minted_certificate",
        fresh_cert,
        0.10,
        (
            f"signing certificate is {cert.age_days} days old and the signer is not "
            "a known publisher; legitimate publishers reuse a key for years because "
            "changing it breaks the upgrade path"
            if fresh_cert
            else f"signing certificate age {cert.age_days} days"
        ),
    )

    shared_permissions = tuple(p for p in DUAL_USE_PERMISSIONS if p in report.permissions)

    present = [s for s in signals if s.present]
    raw = sum(s.weight for s in present)
    total = sum(s.weight for s in signals)
    trojan_score = round(min(raw / total, 1.0) if total else 0.0, 4)

    if publisher_trusted:
        verdict = BenignLookalikeVerdict.LEGITIMATE_PRIVILEGED
        rationale = (
            "Signed by a publisher on the trusted list. The privileged permissions this "
            "app holds are consistent with its stated function, and the signer is "
            "accountable for it. This is a statement about the signer, not a "
            "certification of the code."
        )
    elif trojan_score >= TROJAN_SHAPE_THRESHOLD:
        verdict = BenignLookalikeVerdict.TROJAN_SHAPE
        names = ", ".join(s.id for s in present)
        rationale = (
            f"Holds {len(shared_permissions)} permission(s) that legitimate caller-ID "
            f"and SMS apps also hold, so the permission set alone is not the finding. "
            f"What distinguishes it is intent: {names}."
        )
    else:
        verdict = BenignLookalikeVerdict.INDETERMINATE
        rationale = (
            "The trojan-shape signals are not present in sufficient weight, but this is "
            "not a clean bill of health: the signer is unknown and absence of evidence "
            "is not evidence of innocence."
        )

    return LookalikeAssessment(
        verdict=verdict,
        trojan_score=trojan_score,
        signals=tuple(signals),
        shared_permissions=shared_permissions,
        publisher_trusted=publisher_trusted,
        targeted_financial_packages=tuple(targeted),
        rationale=rationale,
    )
