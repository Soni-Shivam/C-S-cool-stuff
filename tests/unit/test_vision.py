"""Icon impersonation detection (T3.9).

The deterministic perceptual-hash layer is tested directly; the VLM layer is tested
through its grounding rule — that a model naming a brand outside our checkable set is
DROPPED — with the network call stubbed, because a unit test must not depend on a free
endpoint that rate-limits.
"""

from __future__ import annotations

from PIL import Image

from drishti.config import Settings
from drishti.contracts.genai_verdict import VisionMatch
from drishti.m4_genai import vision


def _icon(color: tuple[int, int, int]) -> Image.Image:
    return Image.new("RGB", (192, 192), color)


# ── perceptual hash ──────────────────────────────────────────────────────────
def test_dhash_is_deterministic() -> None:
    icon = _icon((26, 78, 163))
    assert vision._dhash(icon) == vision._dhash(icon.copy())


def test_identical_icons_have_similarity_one() -> None:
    a = _icon((26, 78, 163))
    assert vision._similarity(vision._dhash(a), vision._dhash(a)) == 1.0


def test_perceptual_hash_survives_rescale() -> None:
    """An icon repacked at a different density must still match itself.

    This is the whole reason a difference hash is used rather than an exact hash: the
    same artwork arrives resampled, and a match must survive that.
    """

    base = _icon((13, 71, 161)).resize((512, 512))
    repacked = base.resize((96, 96)).resize((192, 192), Image.Resampling.LANCZOS)
    score = vision._similarity(vision._dhash(base), vision._dhash(repacked))
    assert score >= 0.9


# ── the honesty rule: an unverifiable brand claim is dropped ─────────────────
def test_vlm_brand_outside_the_known_set_is_dropped(monkeypatch) -> None:
    """A model naming a bank we cannot check is an ungrounded claim.

    The rest of the system rejects unverifiable assertions; the vision layer must too,
    or it becomes the one place a hallucinated brand can enter the report.
    """

    class _Resp:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {
                "choices": [
                    {
                        "message": {
                            "content": '{"imitates": true, "brand": "Barclays UK", '
                            '"confidence": 0.99, "why": "blue"}'
                        }
                    }
                ]
            }

    monkeypatch.setattr(vision.httpx, "post", lambda *a, **k: _Resp())
    brand, confidence, notes = vision._vlm_brand(
        _icon((0, 0, 128)),
        Settings(
            groq_api_key="gsk-test",
            vlm_enabled=True,
            vlm_base_url="https://vision.test/v1/chat/completions",
            vlm_api_key="vk-test",
            vlm_model="test-vision",
            _env_file=None,
        ),
    )
    assert brand is None
    assert confidence == 0.0
    assert any("unknown brand" in n for n in notes)


def test_vlm_brand_in_the_known_set_is_kept(monkeypatch) -> None:
    class _Resp:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {
                "choices": [
                    {
                        "message": {
                            "content": 'noise {"imitates": true, "brand": "HDFC Bank", '
                            '"confidence": 0.9, "why": "blue rupee"} trailing'
                        }
                    }
                ]
            }

    monkeypatch.setattr(vision.httpx, "post", lambda *a, **k: _Resp())
    brand, confidence, _ = vision._vlm_brand(
        _icon((13, 71, 161)),
        Settings(
            groq_api_key="gsk-test",
            vlm_enabled=True,
            vlm_base_url="https://vision.test/v1/chat/completions",
            vlm_api_key="vk-test",
            vlm_model="test-vision",
            _env_file=None,
        ),
    )
    assert brand == "HDFC Bank"
    assert confidence == 0.9


def test_no_key_means_no_vlm_call(monkeypatch) -> None:
    called = False

    def _boom(*a, **k):
        nonlocal called
        called = True
        raise AssertionError("must not call the network without a key")

    monkeypatch.setattr(vision.httpx, "post", _boom)
    brand, _confidence, _notes = vision._vlm_brand(
        _icon((0, 0, 0)), Settings(groq_api_key="gsk-test", vlm_api_key=None, _env_file=None)
    )
    assert brand is None
    assert called is False


# ── the whole assessment degrades, never raises ─────────────────────────────
def test_a_missing_icon_yields_an_honest_no_match(tmp_path) -> None:
    """A file with no icon must produce a below-threshold result, not an exception."""
    empty = tmp_path / "no_icon.apk"
    import zipfile

    with zipfile.ZipFile(empty, "w") as z:
        z.writestr("classes.dex", b"not a dex")
    result = vision.assess_icon(
        empty, Settings(groq_api_key="gsk-test", vlm_enabled=False, _env_file=None)
    )
    assert isinstance(result, VisionMatch)
    assert result.matched_brand is None
    assert result.similarity == 0.0
    assert result.threshold == vision._SIMILARITY_THRESHOLD


def test_assess_never_raises_on_a_bad_file(tmp_path) -> None:
    junk = tmp_path / "junk.apk"
    junk.write_bytes(b"this is not a zip")
    result = vision.assess_icon(
        junk, Settings(groq_api_key="gsk-test", vlm_enabled=False, _env_file=None)
    )
    assert result.matched_brand is None
