# Reference brand icons for impersonation detection

`drishti/m4_genai/vision.py` dHashes every `*.png` here and compares an APK's launcher
icon against them. This is the deterministic floor beneath the VLM layer.

## Why this ships empty of PNGs

A brand icon is copyrighted artwork. Committing SBI's or HDFC's launcher icon into a
public repository is a licensing problem we do not need, and a placeholder icon that is
not actually the brand's would make the perceptual-hash layer silently useless — it
would match nothing real.

So the deterministic layer is **inert until populated locally**, and the VLM layer
(which reasons about brand resemblance semantically, without a stored reference image)
does the work in the meantime. This mirrors the honesty rule used for
`known_good_publishers.txt`: an unverified reference is worse than an absent one.

## How to populate it (locally, not committed)

Drop `<brand>.png` files here, named to match the `KNOWN_BRANDS` entries in
`vision.py` (lowercase, spaces to underscores is fine — the stem becomes the match
label). Pull each icon from the real app you obtained legitimately:

    python -c "from drishti.m4_genai.vision import _extract_icon; \
        _extract_icon(Path('sbi_yono.apk')).save('data/kb/brand_icons/sbi.png')"

`data/kb/brand_icons/*.png` is gitignored so a locally-populated set is never committed.
