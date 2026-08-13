from drishti.ml.features import FEATURE_NAMES, extract_features, to_vector
from drishti.static.androguard_adapter import CertInfo, ParsedApk

P = "android.permission."


def test_vector_length_matches_feature_names():
    parsed = ParsedApk(package="com.x", permissions=[P + "INTERNET"])
    v = to_vector(extract_features(parsed))
    assert len(v) == len(FEATURE_NAMES)


def test_dangerous_permission_flags_set():
    parsed = ParsedApk(
        package="com.evil",
        permissions=[P + "RECEIVE_SMS", P + "READ_SMS", P + "BIND_ACCESSIBILITY_SERVICE"],
        cert=CertInfo(self_signed=True),
    )
    feats = extract_features(parsed)
    assert feats["perm_RECEIVE_SMS"] == 1.0
    assert feats["perm_BIND_ACCESSIBILITY_SERVICE"] == 1.0
    assert feats["combo_otp_interception"] == 1.0
    assert feats["cert_self_signed"] == 1.0


def test_benign_has_no_combo_flags():
    parsed = ParsedApk(package="com.good", permissions=[P + "INTERNET", P + "VIBRATE"])
    feats = extract_features(parsed)
    assert all(v == 0.0 for k, v in feats.items() if k.startswith("combo_"))
