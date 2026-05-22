import os

from typing import List


class PinyinWordlist:
    """Runtime index for pinyin -> simplified-Chinese BIP-39 character lookup.

    Loads the bundled ``zh_Hans_pinyin.txt`` resource (generated offline by
    ``tools/generate_chinese_pinyin_data.py``). Each line is::

        <汉字><space><comma-separated pinyin readings with trailing tone digit>

    e.g. ``是 shi4`` or ``行 xing2,hang2,heng2`` (neutral tone has no digit), in
    the SAME order as the BIP-39 simplified-Chinese wordlist, so the line number
    equals the character's BIP-39 index. Heteronyms (多音字) are all indexed so a
    character is reachable by any reading; ``ü`` is spelled ``v``.

    Prefix matching strips the tone digit; candidates are ordered by pinyin, then
    tone (1->4, neutral last), then BIP-39 index. The index is tiny (~2k
    characters), built once and cached, so the linear scans below are trivially
    cheap even on a Pi Zero.
    """

    _instance: "PinyinWordlist" = None
    RESOURCE_FILENAME = "zh_Hans_pinyin.txt"

    @classmethod
    def get_instance(cls) -> "PinyinWordlist":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    NEUTRAL_TONE = 5  # sorts after tones 1-4

    def __init__(self):
        # (base_pinyin, tone, char, bip39_index) for every reading of every char.
        # base_pinyin is the toneless syllable used for prefix matching.
        self._entries: List[tuple] = []
        path = os.path.join(
            os.path.dirname(__file__), "..", "resources", "wordlists", self.RESOURCE_FILENAME
        )
        with open(path, encoding="utf-8") as f:
            for index, line in enumerate(f):
                line = line.rstrip("\n")
                if not line:
                    continue
                char, _, readings = line.partition(" ")
                for reading in readings.split(","):
                    if not reading:
                        continue
                    if reading[-1].isdigit():
                        base, tone = reading[:-1], int(reading[-1])
                    else:
                        base, tone = reading, self.NEUTRAL_TONE
                    self._entries.append((base, tone, char, index))

    def candidate_words(self, pinyin_prefix: str) -> List[str]:
        """Characters whose pinyin (any reading, tone-insensitive) starts with the
        prefix, ordered by pinyin, then tone (1->4, neutral last), then BIP-39 index.
        """
        if not pinyin_prefix:
            return []
        best_key_for_char = {}
        for base, tone, char, index in self._entries:
            if base.startswith(pinyin_prefix):
                key = (base, tone, index)
                if char not in best_key_for_char or key < best_key_for_char[char]:
                    best_key_for_char[char] = key
        return [char for char, _ in sorted(best_key_for_char.items(), key=lambda kv: kv[1])]

    def next_letters(self, pinyin_prefix: str) -> List[str]:
        """The set of letters that can validly follow ``pinyin_prefix`` (tone digit
        ignored). Used to gray out impossible keys."""
        letters = []
        seen = set()
        prefix_len = len(pinyin_prefix)
        for base, tone, char, index in self._entries:
            if base.startswith(pinyin_prefix) and len(base) > prefix_len:
                letter = base[prefix_len]
                if letter not in seen:
                    seen.add(letter)
                    letters.append(letter)
        return letters
