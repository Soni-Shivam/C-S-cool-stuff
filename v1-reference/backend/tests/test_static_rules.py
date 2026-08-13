from drishti.static.rules import (
    detect_permission_combos,
    extract_iocs,
    signature_severity,
)

P = "android.permission."


def test_otp_combo_detected():
    combos = detect_permission_combos({P + "RECEIVE_SMS", P + "READ_SMS"})
    assert any(c.id == "otp_interception" for c in combos)


def test_accessibility_detected():
    combos = detect_permission_combos({P + "BIND_ACCESSIBILITY_SERVICE"})
    assert any(c.id == "accessibility_abuse" for c in combos)


def test_banker_combo_when_overlay_plus_accessibility():
    perms = {P + "SYSTEM_ALERT_WINDOW", P + "BIND_ACCESSIBILITY_SERVICE"}
    combos = detect_permission_combos(perms)
    ids = {c.id for c in combos}
    assert "banker_overlay_accessibility" in ids
    assert "T1417" in {m for c in combos for m in c.mitre}


def test_no_combos_for_benign_permissions():
    assert detect_permission_combos({P + "INTERNET", P + "VIBRATE"}) == []


def test_signature_severity_is_max():
    combos = detect_permission_combos(
        {P + "SYSTEM_ALERT_WINDOW", P + "BIND_ACCESSIBILITY_SERVICE", P + "READ_CONTACTS"}
    )
    assert signature_severity(combos) == 0.95


def test_extract_iocs():
    strings = [
        "config url http://evil.example/c2 here",
        "fallback 185.199.108.153 host",
        "wallet 0x52908400098527886E0F7030069857D2E4169EE7 pay",
        "btc 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 now",
        "nothing here",
    ]
    iocs = extract_iocs(strings)
    assert "http://evil.example/c2" in iocs["urls"]
    assert "185.199.108.153" in iocs["ips"]
    assert "0x52908400098527886E0F7030069857D2E4169EE7" in iocs["crypto"]
    assert "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" in iocs["crypto"]
