from drishti.static.yara_scan import compile_rules, scan_bytes


def test_dynamic_code_loading_rule_matches():
    rules = compile_rules()
    data = b"some bytes ...DexClassLoader... more"
    hits = scan_bytes(data, rules)
    assert "dynamic_code_loading" in hits


def test_sms_interception_rule_matches():
    rules = compile_rules()
    data = b"android.provider.Telephony.SMS_RECEIVED getMessageBody abortBroadcast"
    hits = scan_bytes(data, rules)
    assert "sms_interception" in hits


def test_benign_bytes_no_hits():
    rules = compile_rules()
    hits = scan_bytes(b"hello world just a normal string", rules)
    assert hits == []
