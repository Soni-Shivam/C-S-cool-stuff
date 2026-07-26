from drishti.static.rules import analyze_certificate


def test_self_signed_flagged():
    r = analyze_certificate("CN=Foo", "CN=Foo", is_self_signed=True)
    assert r["self_signed"] is True
    assert "self-signed" in r["note"]


def test_brand_mismatch_detected():
    r = analyze_certificate(
        subject="CN=SBI Secure", issuer="CN=SBI Secure",
        is_self_signed=True, package="com.evil.fakeapp", brands=["SBI"],
    )
    assert r["brand_mismatch"] is True


def test_no_brand_mismatch_when_brand_in_package():
    r = analyze_certificate(
        subject="CN=SBI", issuer="CN=SBI",
        is_self_signed=False, package="com.sbi.official", brands=["SBI"],
    )
    assert r["brand_mismatch"] is False
    assert r["self_signed"] is False
