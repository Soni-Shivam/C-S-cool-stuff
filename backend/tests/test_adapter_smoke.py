import pytest

from drishti.static.androguard_adapter import parse_apk


def test_parse_apk_rejects_non_apk(tmp_path):
    f = tmp_path / "not_an_apk.txt"
    f.write_text("this is not an apk")
    with pytest.raises(ValueError):
        parse_apk(str(f))
