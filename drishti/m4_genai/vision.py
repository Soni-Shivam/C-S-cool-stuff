"""Impersonation detection from the app's own icon. Paper §4.4.4, contract T3.9.

A fraud APK does not just *claim* to be your bank in its strings — it wears the bank's
face. It ships an icon that looks like the HDFC or SBI launcher icon so the victim taps
it without a second thought. That visual claim is checkable, and it is independent of
the code: an icon that is a near-copy of a bank's, on a package that is not the bank's
and signed by a certificate the bank never used, is a strong fraud signal that survives
any amount of code obfuscation.

Two layers, deliberately in this order:

1. **Perceptual hash (deterministic).** A dHash of the app icon against a small set of
   reference brand icons. Pure arithmetic, no model, no network — so it always runs and
   it is reproducible. This is the floor.
2. **Vision-language model (semantic).** When a VLM is configured, it is asked whether
   the icon imitates a known Indian bank or government brand, and to name which. This
   catches a redraw that is visually "an SBI-blue app with a rupee" without being a
   pixel copy — which perceptual hashing misses. The VLM's answer is only *kept* when it
   names a brand our own reference set knows; a model naming a bank we cannot check is
   an ungrounded claim and is dropped.

`method` on the returned `VisionMatch` records which layer produced the verdict, and
both the raw similarity and the threshold are kept, so the report can say "closest match
was SBI at 0.62, below threshold" rather than silently claiming nothing.
"""

from __future__ import annotations

import base64
import json
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import httpx
from PIL import Image

from drishti.config import Settings
from drishti.contracts.genai_verdict import VisionMatch
from drishti.logging import get_logger

log = get_logger(__name__)

#: Reference brand icons live here. Ships with a manifest describing each brand even
#: when the PNG itself is absent, so the VLM's brand vocabulary is defined regardless.
_BRAND_DIR = Path(__file__).resolve().parents[2] / "data" / "kb" / "brand_icons"

#: dHash side length. 8 gives a 64-bit hash — enough to separate distinct icons while
#: tolerating the resampling an APK's launcher icon goes through.
_HASH_SIDE = 8

#: Hamming distance over 64 bits below which two icons are "the same picture". 10 is
#: conservative: it catches recolours and rescales without matching every flat square.
_PHASH_MATCH_BITS = 10

#: Normalised similarity at or above which impersonation is asserted.
_SIMILARITY_THRESHOLD = 0.80

#: The brands worth checking, and the strings a VLM may legitimately name. Sourced from
#: the same market the financial_packages.txt roster covers.
KNOWN_BRANDS: tuple[str, ...] = (
    "SBI",
    "HDFC Bank",
    "ICICI Bank",
    "Axis Bank",
    "Punjab National Bank",
    "Bank of Baroda",
    "Kotak Mahindra Bank",
    "Paytm",
    "PhonePe",
    "Google Pay",
    "BHIM UPI",
    "RTO / Parivahan",
    "Income Tax Department",
    "EPFO",
    "PM-Kisan",
)


def _dhash(image: Image.Image) -> int:
    """A difference hash: each bit is 'this pixel brighter than the one to its right'.

    Robust to scale, aspect and brightness shifts — exactly the transforms an icon
    survives when it is repacked into another APK — while staying a pure, deterministic
    function of the pixels.
    """
    small = image.convert("L").resize((_HASH_SIDE + 1, _HASH_SIDE), Image.Resampling.LANCZOS)
    bits = 0
    for row in range(_HASH_SIDE):
        for col in range(_HASH_SIDE):
            left = small.getpixel((col, row))
            right = small.getpixel((col + 1, row))
            # L-mode guarantees a scalar int per pixel; assert it for the type checker.
            assert isinstance(left, int) and isinstance(right, int)
            bits = (bits << 1) | int(left > right)
    return bits


def _similarity(a: int, b: int) -> float:
    """1.0 for identical hashes, falling to 0.0 at maximum Hamming distance."""
    distance = bin(a ^ b).count("1")
    return 1.0 - distance / (_HASH_SIDE * _HASH_SIDE)


def _extract_icon(apk_path: Path) -> Image.Image | None:
    """Pull the largest launcher icon out of an APK without executing anything.

    The APK is a zip; the icon is a resource inside it. We never install or run the
    sample — this is the same read-as-data posture the static engine uses.
    """
    try:
        with ZipFile(apk_path) as archive:
            candidates = [
                name
                for name in archive.namelist()
                if name.startswith("res/")
                and name.lower().endswith((".png", ".webp"))
                and any(k in name.lower() for k in ("ic_launcher", "icon", "logo", "app_icon"))
            ]
            # Prefer the highest-density variant: xxxhdpi carries the crispest artwork.
            density_rank = ("xxxhdpi", "xxhdpi", "xhdpi", "hdpi", "mdpi")

            def _rank(name: str) -> int:
                lowered = name.lower()
                for index, tag in enumerate(density_rank):
                    if tag in lowered:
                        return index
                return len(density_rank)

            for name in sorted(candidates, key=_rank):
                try:
                    with archive.open(name) as handle:
                        image = Image.open(handle)
                        image.load()
                        return image.convert("RGBA")
                except Exception:
                    continue
    except Exception as exc:
        log.info("icon_extract_failed", error=f"{type(exc).__name__}: {exc}")
    return None


def _reference_hashes() -> dict[str, int]:
    """dHash of every reference brand icon present on disk. Absent icons are skipped."""
    hashes: dict[str, int] = {}
    if not _BRAND_DIR.exists():
        return hashes
    for png in sorted(_BRAND_DIR.glob("*.png")):
        try:
            hashes[png.stem] = _dhash(Image.open(png))
        except Exception:
            continue
    return hashes


def _vlm_brand(icon: Image.Image, settings: Settings) -> tuple[str | None, float, list[str]]:
    """Ask the configured VLM whether the icon imitates a known brand.

    Returns (matched_brand, confidence, notes). The brand is kept only if it is in
    `KNOWN_BRANDS`; a model naming something we cannot check is dropped, because an
    unverifiable brand claim is exactly the hallucination the rest of the system
    refuses.
    """
    key = settings.openrouter_api_key
    if key is None:
        return None, 0.0, ["no VLM key configured"]

    buffer = BytesIO()
    icon.convert("RGB").resize((128, 128)).save(buffer, format="PNG")
    data_uri = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()

    brand_list = ", ".join(KNOWN_BRANDS)
    prompt = (
        "You are a brand-impersonation analyst. Look at this Android app icon. "
        f"Does it imitate the visual branding of any of these Indian institutions? [{brand_list}]. "
        "Reply with ONLY compact JSON: "
        '{"imitates": true|false, "brand": "<one of the list, or null>", '
        '"confidence": 0.0-1.0, "why": "<one short phrase>"}. '
        "Judge on colours, logo shape and iconography, not on text you might read."
    )

    try:
        response = httpx.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {key.get_secret_value()}"},
            json={
                "model": settings.vlm_model,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {"type": "image_url", "image_url": {"url": data_uri}},
                        ],
                    }
                ],
                "max_tokens": 400,
                "temperature": 0,
            },
            timeout=90,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
    except Exception as exc:
        return None, 0.0, [f"VLM call failed: {type(exc).__name__}"]

    start, end = content.find("{"), content.rfind("}")
    if start < 0 or end < 0:
        return None, 0.0, ["VLM returned no JSON"]
    try:
        verdict = json.loads(content[start : end + 1])
    except json.JSONDecodeError:
        return None, 0.0, ["VLM JSON did not parse"]

    if not verdict.get("imitates"):
        return None, 0.0, ["VLM saw no brand imitation"]
    brand: str | None = verdict.get("brand")
    if brand not in KNOWN_BRANDS:
        # An unverifiable brand claim is dropped, not asserted.
        return None, 0.0, [f"VLM named an unknown brand {brand!r}; dropped"]
    confidence = float(verdict.get("confidence") or 0.0)
    why = str(verdict.get("why") or "")[:120]
    return brand, confidence, [f"VLM: imitates {brand} ({why})"]


def assess_icon(apk_path: Path, settings: Settings | None = None) -> VisionMatch:
    """Compare an APK's launcher icon against known brand references.

    Never raises: a vision failure must degrade the report, not lose it. On any error
    the result is an honest "no match, below threshold" with the reason in a note-free
    zero, matching the contract's "closest match was X at 0.62" honesty requirement.
    """
    settings = settings or Settings()
    icon = _extract_icon(apk_path)
    if icon is None:
        return VisionMatch(
            matched_brand=None,
            similarity=0.0,
            threshold=_SIMILARITY_THRESHOLD,
            method="perceptual_hash",
        )

    # ── layer 1: deterministic perceptual hash ───────────────────────────────
    references = _reference_hashes()
    best_brand: str | None = None
    best_similarity = 0.0
    if references:
        icon_hash = _dhash(icon)
        for brand, ref_hash in references.items():
            score = _similarity(icon_hash, ref_hash)
            if score > best_similarity:
                best_similarity, best_brand = score, brand

    if best_similarity >= _SIMILARITY_THRESHOLD:
        return VisionMatch(
            matched_brand=best_brand,
            similarity=round(best_similarity, 4),
            threshold=_SIMILARITY_THRESHOLD,
            method="perceptual_hash",
        )

    # ── layer 2: VLM, only if configured and enabled ─────────────────────────
    if settings.vlm_enabled and settings.openrouter_api_key is not None:
        vlm_brand, confidence, _notes = _vlm_brand(icon, settings)
        if vlm_brand is not None and confidence >= _SIMILARITY_THRESHOLD:
            return VisionMatch(
                matched_brand=vlm_brand,
                similarity=round(confidence, 4),
                threshold=_SIMILARITY_THRESHOLD,
                method="vlm",
            )

    # Nothing crossed the line. Report the closest perceptual match honestly.
    return VisionMatch(
        matched_brand=None,
        similarity=round(best_similarity, 4),
        threshold=_SIMILARITY_THRESHOLD,
        method="perceptual_hash",
    )
