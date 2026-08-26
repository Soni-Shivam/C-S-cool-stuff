#!/usr/bin/env python3
"""Draw the decoy's raster launcher icon.

WHY THIS EXISTS AT ALL
======================
`drishti/m4_genai/vision.py` detects icon impersonation, and it reads the icon out of
the APK's zip by looking for a `.png`/`.webp` under `res/` whose name contains
`ic_launcher`/`icon`/`logo`. A **vector drawable compiles to XML, not to a raster**, so
a decoy whose only icon is `res/drawable/ic_challan.xml` gives `_extract_icon()` nothing
to hash and nothing to send to the vision model — the impersonation layer silently
returns "no match" for the one sample it was built to catch.

This script produces that missing raster at
`app/src/main/res/mipmap-xxxhdpi/ic_launcher.png`.

WHAT IT DRAWS, AND WHAT IT DELIBERATELY DOES NOT
================================================
A *lookalike*: a deep-navy rounded square, a red corner flash, an embossed seal ring and
a large white rupee glyph. That is the visual grammar of an Indian bank / government
payment app — navy + red + rupee — and it is exactly what the fraud family copies.

It is **not** any real institution's logo. No bank's actual mark, wordmark, letterform
or trade dress is reproduced here, and none may be added: reproducing a real logo would
put a copyrighted asset in this repository for no analytical gain, since the vision layer
is judging *colour, shape and iconography*, which a lookalike carries just as well.
See `canary/decoy-challan/README.md`.

An icon is a picture. It grants the decoy no capability, adds no code path, and leaves
the inertness gate's claim untouched — `verify_inert.sh` scans `app/src/main/java` and
has nothing to say about a PNG.

    uv run python canary/decoy-challan/tools/make_launcher_icon.py

Deterministic: same output bytes on every run, so the committed PNG can be regenerated
and diffed.
"""

from __future__ import annotations

import glob
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

#: xxxhdpi launcher icons are 192x192. Drawn at 4x and downsampled, because PIL has no
#: antialiased primitives — supersampling is how the curves stop looking like stairs.
SIDE = 192
SUPERSAMPLE = 4

#: Blue and red: the palette of nearly every Indian retail-bank and wallet app. A family
#: resemblance, not a copy of any one brand's specified colour values.
#:
#: This particular composition — blue field, red block in the upper right, white rupee —
#: was CHOSEN ON MEASUREMENT, not taste. Three candidate designs were each put to the
#: configured VLM five times; this one is the only one that named a brand on every call
#: that the endpoint answered at all, and the only one that reached 0.9. The numbers and
#: the variance are in docs/DEMO_SCRIPT.md, because a free endpoint's confidence is not
#: something to quote as if it were stable.
BLUE_TOP = (0, 60, 140)
BLUE_BOTTOM = (0, 38, 96)
ACCENT_RED = (216, 28, 38)
WHITE = (255, 255, 255)

OUT = Path(__file__).resolve().parents[1] / "app/src/main/res/mipmap-xxxhdpi/ic_launcher.png"


#: Tried in order before falling back to a filesystem sweep. Clean bold sans faces —
#: a display or serif face draws a rupee the vision model reads as decoration.
PREFERRED_FONTS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/croscore/Arimo-Bold.ttf",
    "/usr/share/fonts/truetype/crosextra/Carlito-Bold.ttf",
)


def _has_real_glyph(font: ImageFont.FreeTypeFont, char: str) -> bool:
    """True only if `char` renders as itself, not as .notdef.

    `getmask(char).getbbox() is not None` is NOT enough, and getting this wrong is how
    the first version of this icon shipped a tofu box where the rupee should be: a font
    with no U+20B9 renders the .notdef *rectangle*, which is a perfectly good non-empty
    bitmap. Comparing against a codepoint nothing maps (U+E000, private use) tells the
    two apart — identical bitmaps mean both fell through to .notdef.
    """
    try:
        glyph, notdef = font.getmask(char), font.getmask("")
        if glyph.getbbox() is None:
            return False
        return not (glyph.size == notdef.size and bytes(glyph) == bytes(notdef))
    except Exception:
        return False


def _rupee_font(size: int) -> ImageFont.FreeTypeFont | None:
    """A TrueType face that actually draws U+20B9, or None if this machine has none.

    Most system fonts do not carry the rupee sign. Rather than hardcode a path that
    exists on one laptop, try the preferred faces and then probe — and return None if
    nothing can draw it, so the caller falls back to primitives and the icon is never
    silently missing its motif.
    """
    candidates = list(PREFERRED_FONTS) + sorted(glob.glob("/usr/share/fonts/**/*.ttf", recursive=True))
    for path in candidates:
        # Text faces only. The maths and symbol fonts (cmsy10, msam10, wasy10) map that
        # codepoint to something that is not a rupee at all.
        if any(bad in path.lower() for bad in ("lyx", "mathjax", "symbol", "dingbat")):
            continue
        try:
            font = ImageFont.truetype(path, size)
        except Exception:
            continue
        if _has_real_glyph(font, "₹"):
            return font
    return None


def _draw_rupee_primitive(draw: ImageDraw.ImageDraw, cx: int, cy: int, height: int) -> None:
    """Draw ₹ from rectangles and arcs, for a machine with no rupee-capable font.

    Two horizontal bars, a bowl hanging off the upper one, and a leg falling to the
    lower right — the construction of the Devanagari-derived glyph, close enough that a
    vision model reads "rupee".
    """
    stroke = max(2, height // 9)
    half_w = int(height * 0.34)
    top = cy - height // 2
    left, right = cx - half_w, cx + half_w

    draw.rectangle([left, top, right, top + stroke], fill=WHITE)
    bar2 = top + int(height * 0.26)
    draw.rectangle([left, bar2, right, bar2 + stroke], fill=WHITE)

    bowl_bottom = top + int(height * 0.58)
    draw.arc([left, top, left + 2 * (right - left) // 2, bowl_bottom], start=-80, end=90, fill=WHITE, width=stroke)
    draw.line([(left, top), (left, bowl_bottom)], fill=WHITE, width=stroke)
    draw.line(
        [(left + int(height * 0.10), bowl_bottom - stroke), (right, cy + height // 2)],
        fill=WHITE,
        width=stroke,
    )


def build() -> Path:
    """Render the icon and write it to the decoy's mipmap directory."""
    side = SIDE * SUPERSAMPLE
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))

    # Vertical blue gradient, painted a row at a time.
    gradient = Image.new("RGB", (1, side))
    for y in range(side):
        t = y / (side - 1)
        gradient.putpixel(
            (0, y),
            tuple(int(a + (b - a) * t) for a, b in zip(BLUE_TOP, BLUE_BOTTOM, strict=True)),  # type: ignore[arg-type]
        )
    gradient = gradient.resize((side, side))

    # A squircle-ish rounded square is what reads as "modern launcher icon".
    mask = Image.new("L", (side, side), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, side - 1, side - 1], radius=int(side * 0.22), fill=255)
    canvas.paste(gradient, (0, 0), mask)

    draw = ImageDraw.Draw(canvas)

    # The red block in the upper right. Drawn on its own layer and masked back to the
    # rounded square, so it cannot bleed past the icon's silhouette.
    #
    # A hard-edged two-colour split, rather than the softer corner flash the first
    # version used: of the three candidates measured, the split is the one the vision
    # model read as deliberate brand geometry every time it answered.
    block = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    ImageDraw.Draw(block).rectangle(
        [int(side * 0.52), 0, side, int(side * 0.48)],
        fill=(*ACCENT_RED, 255),
    )
    canvas.paste(block, (0, 0), Image.composite(block.split()[3], Image.new("L", (side, side), 0), mask))

    glyph_height = int(side * 0.46)
    font = _rupee_font(glyph_height)
    if font is not None:
        box = draw.textbbox((0, 0), "₹", font=font)
        draw.text(
            ((side - (box[2] - box[0])) // 2 - box[0], (side - (box[3] - box[1])) // 2 - box[1]),
            "₹",
            font=font,
            fill=WHITE,
        )
    else:
        _draw_rupee_primitive(draw, side // 2, side // 2, glyph_height)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    canvas.resize((SIDE, SIDE), Image.Resampling.LANCZOS).save(OUT, format="PNG", optimize=True)
    return OUT


if __name__ == "__main__":
    written = build()
    print(f"wrote {written} ({written.stat().st_size} bytes)")
