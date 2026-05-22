#!/usr/bin/env python3
"""
Offline tool: build a tiny NotoSansSC-Regular.ttf subset for SeedSigner.

DEV-TIME ONLY. Not imported by the firmware.

Noto Sans SC (SIL OFL 1.1) is huge (~10MB+, ~65k glyphs). The device only ever
needs to render the 2048 BIP-39 simplified-Chinese characters (for the pinyin
seed-entry candidate list and for displaying / verifying a Chinese seed), plus
basic ASCII so the same font can also draw pinyin letters and digits when needed.

We subset to exactly that glyph set, shrinking the file to a few hundred KB so it
loads quickly on a Pi Zero. Output:
    src/seedsigner/resources/fonts/NotoSansSC-Regular.ttf

Run:  python tools/subset_cjk_font.py
Requires (dev only):  fonttools, requests/urllib
"""
import os
import pathlib
import urllib.request

from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORDLIST_PATH = REPO_ROOT / "src" / "seedsigner" / "resources" / "wordlists" / "chinese_simplified.txt"
FONTS_DIR = REPO_ROOT / "src" / "seedsigner" / "resources" / "fonts"
OUTPUT_PATH = FONTS_DIR / "NotoSansSC-Regular.ttf"

CACHE_DIR = pathlib.Path(__file__).resolve().parent / "_cache"
SRC_FONT_PATH = CACHE_DIR / "NotoSansSC[wght].ttf"
# Canonical variable font from the Google Fonts repo (SIL OFL 1.1).
SRC_FONT_URL = "https://github.com/google/fonts/raw/main/ofl/notosanssc/NotoSansSC%5Bwght%5D.ttf"


def ensure_source_font() -> pathlib.Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if SRC_FONT_PATH.exists() and SRC_FONT_PATH.stat().st_size > 1_000_000:
        print(f"Using cached source font: {SRC_FONT_PATH} ({SRC_FONT_PATH.stat().st_size:,} bytes)")
        return SRC_FONT_PATH
    print(f"Downloading Noto Sans SC variable font from {SRC_FONT_URL}")
    req = urllib.request.Request(SRC_FONT_URL, headers={"User-Agent": "Mozilla/5.0"})
    data = urllib.request.urlopen(req, timeout=180).read()
    SRC_FONT_PATH.write_bytes(data)
    print(f"  saved {len(data):,} bytes -> {SRC_FONT_PATH}")
    return SRC_FONT_PATH


def target_characters() -> set[str]:
    words = [w for w in WORDLIST_PATH.read_text(encoding="utf-8").split("\n") if w.strip()]
    assert len(words) == 2048, f"expected 2048 words, got {len(words)}"
    chars = set("".join(words))
    # Basic ASCII (printable) so the same font can render pinyin / digits / punctuation.
    chars |= {chr(c) for c in range(0x20, 0x7F)}
    return chars


def main():
    src = ensure_source_font()
    chars = target_characters()
    print(f"target glyph set: {len(chars)} unique characters")

    font = TTFont(src)

    # Pin the variable weight axis to Regular (400) and flatten to a static font.
    if "fvar" in font:
        print("instancing variable font at wght=400 ...")
        instancer.instantiateVariableFont(font, {"wght": 400}, inplace=True)

    subsetter = subset.Subsetter(options=subset.Options(
        glyph_names=False,
        recalc_bounds=True,
        recalc_timestamp=False,
        drop_tables=["GPOS", "GSUB", "GDEF"],  # not needed for simple text rendering
        name_IDs=[1, 2, 4, 6],
        notdef_outline=True,
        layout_features=[],
    ))
    subsetter.populate(text="".join(sorted(chars)))
    subsetter.subset(font)

    FONTS_DIR.mkdir(parents=True, exist_ok=True)
    font.save(OUTPUT_PATH)
    size = OUTPUT_PATH.stat().st_size
    print(f"wrote {OUTPUT_PATH} ({size:,} bytes)")

    # Verify every required character has a glyph in the output cmap.
    out = TTFont(OUTPUT_PATH)
    cmap = out.getBestCmap()
    missing = [c for c in chars if ord(c) not in cmap]
    if missing:
        raise SystemExit(f"FATAL: {len(missing)} chars missing from subset, e.g. {missing[:20]}")
    print(f"verified: all {len(chars)} target characters present in subset cmap")


if __name__ == "__main__":
    main()
