"""M5 feature extraction. Pure: turns a ParsedApk into a fixed-order numeric
feature vector. No APK I/O, no model — fully testable, and the same function
is used both for training-set extraction and inference so there is no skew."""
from drishti.static.androguard_adapter import ParsedApk
from drishti.static.rules import PERMISSION_COMBOS, detect_permission_combos, extract_iocs

# Curated dangerous permissions tracked as individual one-hot features.
DANGEROUS_PERMISSIONS = [
    "RECEIVE_SMS", "READ_SMS", "SEND_SMS",
    "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES", "READ_CONTACTS", "READ_PHONE_STATE",
    "RECORD_AUDIO", "CAMERA", "READ_EXTERNAL_STORAGE", "INTERNET",
    "QUERY_ALL_PACKAGES", "GET_ACCOUNTS", "USE_FULL_SCREEN_INTENT",
]

_COMBO_IDS = [c.id for c in PERMISSION_COMBOS]

# Deterministic, stable feature order. Never reorder — models are trained on it.
FEATURE_NAMES: list[str] = (
    [f"perm_{p}" for p in DANGEROUS_PERMISSIONS]
    + [f"combo_{cid}" for cid in _COMBO_IDS]
    + [
        "num_permissions", "num_activities", "num_services", "num_receivers",
        "num_providers", "num_exported", "num_strings",
        "num_urls", "num_ips", "num_crypto", "cert_self_signed",
    ]
)


def extract_features(parsed: ParsedApk) -> dict[str, float]:
    short_perms = {p.split(".")[-1] for p in parsed.permissions}
    combos = {c.id for c in detect_permission_combos(parsed.permissions)}
    iocs = extract_iocs(parsed.strings)

    feats: dict[str, float] = {}
    for p in DANGEROUS_PERMISSIONS:
        feats[f"perm_{p}"] = 1.0 if p in short_perms else 0.0
    for cid in _COMBO_IDS:
        feats[f"combo_{cid}"] = 1.0 if cid in combos else 0.0
    feats["num_permissions"] = float(len(parsed.permissions))
    feats["num_activities"] = float(len(parsed.activities))
    feats["num_services"] = float(len(parsed.services))
    feats["num_receivers"] = float(len(parsed.receivers))
    feats["num_providers"] = float(len(parsed.providers))
    feats["num_exported"] = float(len(parsed.exported))
    feats["num_strings"] = float(len(parsed.strings))
    feats["num_urls"] = float(len(iocs["urls"]))
    feats["num_ips"] = float(len(iocs["ips"]))
    feats["num_crypto"] = float(len(iocs["crypto"]))
    feats["cert_self_signed"] = 1.0 if parsed.cert.self_signed else 0.0
    return feats


def to_vector(feats: dict[str, float]) -> list[float]:
    return [float(feats.get(name, 0.0)) for name in FEATURE_NAMES]
