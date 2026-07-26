import pytest

from drishti.ledger import Ledger
from drishti.ml import MalwareClassifier, classify, extract_features, train_baseline
from drishti.static.androguard_adapter import CertInfo, ParsedApk

P = "android.permission."
TS = "2026-07-26T00:00:00Z"


@pytest.fixture(scope="module")
def clf():
    return train_baseline(n=800)


def _banker():
    return ParsedApk(
        package="com.evil.fakebank",
        permissions=[P + "SYSTEM_ALERT_WINDOW", P + "BIND_ACCESSIBILITY_SERVICE",
                     P + "RECEIVE_SMS", P + "READ_SMS", P + "REQUEST_INSTALL_PACKAGES"],
        strings=["http://evil/c2", "1.2.3.4"], cert=CertInfo(self_signed=True),
    )


def _benign():
    return ParsedApk(package="com.good.notes", permissions=[P + "INTERNET"])


def test_pcal_in_unit_interval(clf):
    p = clf.predict_proba(extract_features(_banker()))
    assert 0.0 <= p <= 1.0


def test_banker_scores_higher_than_benign(clf):
    p_bad = clf.predict_proba(extract_features(_banker()))
    p_good = clf.predict_proba(extract_features(_benign()))
    assert p_bad > p_good
    assert p_bad > 0.5


def test_save_load_roundtrip(clf, tmp_path):
    path = tmp_path / "m.joblib"
    clf.save(path)
    loaded = MalwareClassifier.load(path)
    feats = extract_features(_banker())
    assert loaded.predict_proba(feats) == pytest.approx(clf.predict_proba(feats), abs=1e-9)


def test_classify_appends_ml_signal_node(clf):
    led = Ledger()
    res = classify(_banker(), clf, led, TS)
    assert res.label == "malicious"
    assert any(n.type == "ml_signal" for n in led.nodes)
