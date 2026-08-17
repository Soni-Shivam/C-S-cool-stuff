"""The sink taxonomy.

docs/PHASE_1_STATIC_ENGINE.md T1.4, which calls this "the most valuable file here".

A **sink** is an API whose invocation is the thing an analyst actually cares about:
sending an SMS, loading a DEX, reading the clipboard, reaching the network. The call
graph exists to answer one question about each of them — *can this be reached from a
lifecycle entrypoint?* — because a sink reachable only from dead library code is much
weaker evidence than one reachable from `onReceive` of a registered SMS receiver.

Three things every entry carries, and each is load-bearing downstream:

  * `marker` — the substring matched against method signatures. Kept as a fragment
    (`SmsManager;->sendTextMessage`) rather than a full descriptor, because obfuscators
    rewrite parameter types far more often than they rewrite framework class names.
  * `mitre` — flows into the technique mapper and the STIX export.
  * `severity` — feeds the `G` term and orders what the LLM is asked about first, since
    the prompt budget is finite.

**This file is observational.** It enumerates APIs to *watch for*; nothing here calls
them. Adding a sink widens detection, never capability.
"""

from __future__ import annotations

from dataclasses import dataclass

from drishti.contracts.static_report import Severity


@dataclass(frozen=True)
class Sink:
    """One watched API."""

    sink_id: str
    marker: str
    category: str
    severity: Severity
    mitre: str
    description: str


#: The taxonomy. PHASE_1's Definition of Done requires >= 18; keeping headroom above that
#: matters because a sink the corpus never exercises costs nothing, while a missing one
#: is a blind spot that only shows up as a sample scoring lower than it should.
SINKS: tuple[Sink, ...] = (
    # ── package / environment probing — what the frontier answers with ──────
    Sink(
        "pkg_query",
        "PackageManager;->getPackageInfo",
        "probe",
        Severity.MEDIUM,
        "T1418",
        "Asks whether a specific package is installed",
    ),
    Sink(
        "pkg_list",
        "PackageManager;->getInstalledPackages",
        "probe",
        Severity.MEDIUM,
        "T1418",
        "Enumerates every installed package",
    ),
    Sink(
        "pkg_resolve",
        "PackageManager;->resolveActivity",
        "probe",
        Severity.LOW,
        "T1418",
        "Resolves which app handles an intent",
    ),
    # ── dynamic code loading — the dropper shape ────────────────────────────
    Sink(
        "dex_load",
        "DexClassLoader;-><init>",
        "code_load",
        Severity.CRITICAL,
        "T1407",
        "Loads a DEX at runtime; classic secondary-payload delivery",
    ),
    Sink(
        "dex_load_path",
        "PathClassLoader;-><init>",
        "code_load",
        Severity.HIGH,
        "T1407",
        "Loads code from a path at runtime",
    ),
    Sink(
        "native_load",
        "System;->loadLibrary",
        "code_load",
        Severity.MEDIUM,
        "T1407",
        "Loads a native library, moving logic out of reach of DEX analysis",
    ),
    Sink(
        "reflection",
        "java/lang/reflect/Method;->invoke",
        "code_load",
        Severity.MEDIUM,
        "T1406",
        "Invokes a method reflectively, hiding the call target from static analysis",
    ),
    # ── exfiltration channels ───────────────────────────────────────────────
    Sink(
        "network",
        "HttpURLConnection;->connect",
        "network",
        Severity.MEDIUM,
        "T1437",
        "Opens an HTTP connection",
    ),
    Sink(
        "network_socket",
        "java/net/Socket;-><init>",
        "network",
        Severity.MEDIUM,
        "T1095",
        "Opens a raw socket, bypassing HTTP inspection",
    ),
    Sink(
        "network_okhttp",
        "okhttp3/OkHttpClient;->newCall",
        "network",
        Severity.MEDIUM,
        "T1437",
        "Issues a request through OkHttp",
    ),
    # ── SMS: the OTP path ───────────────────────────────────────────────────
    Sink(
        "sms_body",
        "SmsMessage;->getMessageBody",
        "sms",
        Severity.HIGH,
        "T1636",
        "Reads the body of a received SMS — the OTP interception primitive",
    ),
    Sink(
        "sms_send",
        "SmsManager;->sendTextMessage",
        "sms",
        Severity.CRITICAL,
        "T1582",
        "Sends an SMS without user interaction",
    ),
    Sink(
        "sms_query",
        "content://sms",
        "sms",
        Severity.HIGH,
        "T1636",
        "Queries the SMS content provider",
    ),
    # ── UI abuse ────────────────────────────────────────────────────────────
    Sink(
        "overlay",
        "WindowManager;->addView",
        "ui",
        Severity.CRITICAL,
        "T1417",
        "Draws a window over other apps — the credential-overlay primitive",
    ),
    Sink(
        "accessibility",
        "AccessibilityService;->onAccessibilityEvent",
        "ui",
        Severity.CRITICAL,
        "T1417",
        "Observes UI events app-wide; the strongest single capability on Android",
    ),
    Sink(
        "notification_listen",
        "NotificationListenerService;->onNotificationPosted",
        "ui",
        Severity.HIGH,
        "T1636",
        "Reads notification content, including OTPs",
    ),
    Sink(
        "screen_capture",
        "MediaProjection;->createVirtualDisplay",
        "ui",
        Severity.HIGH,
        "T1513",
        "Captures the screen",
    ),
    # ── device and identity harvesting ──────────────────────────────────────
    Sink(
        "device_id",
        "TelephonyManager;->getDeviceId",
        "identity",
        Severity.MEDIUM,
        "T1426",
        "Reads a hardware identifier",
    ),
    Sink(
        "sim_serial",
        "TelephonyManager;->getSimSerialNumber",
        "identity",
        Severity.MEDIUM,
        "T1426",
        "Reads the SIM serial — often a geo/logic-bomb gate",
    ),
    Sink(
        "accounts",
        "AccountManager;->getAccountsByType",
        "identity",
        Severity.HIGH,
        "T1636",
        "Enumerates configured accounts",
    ),
    Sink(
        "contacts",
        "content://com.android.contacts",
        "identity",
        Severity.HIGH,
        "T1636",
        "Queries the contacts provider",
    ),
    Sink(
        "call_log", "content://call_log", "identity", Severity.HIGH, "T1636", "Queries the call log"
    ),
    Sink(
        "location",
        "LocationManager;->getLastKnownLocation",
        "identity",
        Severity.MEDIUM,
        "T1430",
        "Reads device location",
    ),
    # ── clipboard and crypto ────────────────────────────────────────────────
    Sink(
        "clipboard",
        "ClipboardManager;->getPrimaryClip",
        "clipboard",
        Severity.HIGH,
        "T1414",
        "Reads the clipboard — the wallet-address-swap primitive",
    ),
    Sink(
        "crypto",
        "javax/crypto/Cipher;->doFinal",
        "crypto",
        Severity.MEDIUM,
        "T1521",
        "Encrypts or decrypts; hooking it yields plaintext before it leaves the device",
    ),
    # ── execution and persistence ───────────────────────────────────────────
    Sink(
        "exec",
        "java/lang/Runtime;->exec",
        "exec",
        Severity.HIGH,
        "T1623",
        "Executes a shell command",
    ),
    Sink(
        "process_builder",
        "java/lang/ProcessBuilder;->start",
        "exec",
        Severity.HIGH,
        "T1623",
        "Starts a process",
    ),
    Sink(
        "device_admin",
        "DevicePolicyManager;->lockNow",
        "persistence",
        Severity.HIGH,
        "T1626",
        "Exercises device-admin authority; commonly used to resist uninstall",
    ),
    Sink(
        "component_toggle",
        "PackageManager;->setComponentEnabledSetting",
        "persistence",
        Severity.MEDIUM,
        "T1628",
        "Enables or hides its own components at runtime",
    ),
)

#: id -> marker, the shape the call-graph walker matches against.
SINK_SIGNATURES: dict[str, str] = {sink.sink_id: sink.marker for sink in SINKS}

#: id -> Sink, for severity and MITRE lookup without a linear scan.
SINK_BY_ID: dict[str, Sink] = {sink.sink_id: sink for sink in SINKS}


def severity_of(sink_id: str) -> Severity:
    """Severity for a sink id, defaulting to LOW for anything unrecognised.

    Defaults low deliberately: an unknown sink must never inflate a score by accident.
    """
    sink = SINK_BY_ID.get(sink_id)
    return sink.severity if sink else Severity.LOW
