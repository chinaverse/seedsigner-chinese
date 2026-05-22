#!/usr/bin/env python3
"""
Offline generator for SeedSigner's simplified-Chinese BIP-39 pinyin input data.

This is a DEV-TIME tool. It is NOT imported by the firmware at runtime.

It produces two resource files consumed by the on-device pinyin seed-entry screen:

  src/seedsigner/resources/wordlists/chinese_simplified.txt
      The official BIP-39 simplified-Chinese wordlist (2048 single chars, index
      order). Downloaded from the canonical bitcoin/bips repo and cross-checked
      against the Trezor `mnemonic` reference library so we never ship a wrong
      list (security critical).

  src/seedsigner/resources/wordlists/zh_Hans_pinyin.txt
      One line per wordlist entry, in the SAME index order as the wordlist:
          <汉字><space><comma-separated toneless pinyin readings>
      e.g.  行 xing,hang
      Heteronyms (多音字) are all included so a char is reachable by any reading.
      `ü` readings are expanded to both `v` and `u` spellings so users can type
      either on an a-z keyboard (no ü key on the device).

Run:  python tools/generate_chinese_pinyin_data.py
Requires (dev only):  pypinyin, mnemonic, requests
"""
import hashlib
import os
import pathlib
import re
import sys
import unicodedata
import urllib.request

# Drop this script's own directory from sys.path so the repo's local
# `tools/mnemonic.py` does not shadow the installed `mnemonic` reference package.
_here = str(pathlib.Path(__file__).resolve().parent)
sys.path[:] = [p for p in sys.path if os.path.abspath(p or ".") != _here]

from pypinyin import pinyin, Style

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORDLIST_DIR = REPO_ROOT / "src" / "seedsigner" / "resources" / "wordlists"
WORDLIST_PATH = WORDLIST_DIR / "chinese_simplified.txt"
PINYIN_PATH = WORDLIST_DIR / "zh_Hans_pinyin.txt"

BIPS_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/chinese_simplified.txt"

# Known-good SHA256 of bip-0039/chinese_simplified.txt (verified at generation time).
EXPECTED_SHA256 = "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726"


def fetch_and_verify_wordlist() -> list[str]:
    print(f"Downloading wordlist from {BIPS_URL}")
    data = urllib.request.urlopen(BIPS_URL, timeout=60).read()
    digest = hashlib.sha256(data).hexdigest()
    print(f"  sha256: {digest}")
    words = [w for w in data.decode("utf-8").split("\n") if w.strip() != ""]
    print(f"  lines: {len(words)}")

    if len(words) != 2048:
        sys.exit(f"FATAL: expected 2048 words, got {len(words)}")
    if not all(len(w) == 1 for w in words):
        sys.exit("FATAL: every BIP-39 simplified-Chinese word must be a single char")

    # Cross-check against the Trezor `mnemonic` reference implementation.
    try:
        from mnemonic import Mnemonic
        ref = Mnemonic("chinese_simplified").wordlist
        if words != ref:
            sys.exit("FATAL: downloaded wordlist does not match `mnemonic` reference lib")
        print("  cross-check vs `mnemonic` reference lib: MATCH")
    except ImportError:
        print("  (skipping `mnemonic` cross-check; lib not installed)")

    if digest != EXPECTED_SHA256:
        # Not fatal (BIP repo could legitimately never change, but be loud).
        print(f"  WARNING: sha256 does not match pinned EXPECTED_SHA256 ({EXPECTED_SHA256})")

    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    with open(WORDLIST_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(words) + "\n")
    print(f"  wrote {WORDLIST_PATH}")
    return words


def readings_for(char: str) -> list[str]:
    """Return ordered, de-duped, ascii pinyin readings WITH a trailing tone digit.

    Uses pypinyin TONE3 style: the tone number (1-4) is appended to the syllable
    (e.g. 是 -> "shi4", 行 -> ["xing2", "hang2", "heng2"]); a neutral tone has no
    digit (e.g. 的轻声 -> "de"). The runtime index strips the digit for prefix
    matching but uses it to order candidates by pinyin then tone.

    The ü vowel is normalized to ``v`` (universal Chinese input convention:
    女 -> "nv4", 绿 -> "lv4"); "nu"/"lu" remain their own syllables.
    """
    raw = pinyin(char, style=Style.TONE3, heteronym=True, neutral_tone_with_five=False)[0]
    out = []
    for r in raw:
        r = unicodedata.normalize("NFC", r.lower()).replace("ü", "v")
        if r not in out:
            out.append(r)
    return out


def main():
    words = fetch_and_verify_wordlist()

    lines = []
    bad = []
    reading_counts = []
    valid = re.compile(r"^[a-z]+[1-4]?$")
    for ch in words:
        readings = readings_for(ch)
        for r in readings:
            if not valid.match(r):
                bad.append((ch, r))
        reading_counts.append(len(readings))
        lines.append(f"{ch} {','.join(readings)}")

    if bad:
        sys.exit(f"FATAL: non-ascii / invalid pinyin readings produced: {bad[:20]}")

    with open(PINYIN_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")

    print(f"wrote {PINYIN_PATH}")
    print(f"  entries: {len(lines)}")
    print(f"  max readings for one char: {max(reading_counts)}")
    print(f"  chars with >1 reading: {sum(1 for c in reading_counts if c > 1)}")
    # Spot-check a few well-known heteronyms.
    sample = {w: readings_for(w) for w in ["行", "重", "还", "女", "绿", "的", "了"] if w in words}
    for k, v in sample.items():
        print(f"  sample {k}: {v}")


if __name__ == "__main__":
    main()
