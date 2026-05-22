import os

from typing import List


class PinyinWordlist:
    """Runtime index for pinyin -> simplified-Chinese BIP-39 character lookup.

    Loads the bundled ``zh_Hans_pinyin.txt`` resource (generated offline by
    ``tools/generate_chinese_pinyin_data.py``). Each line is::

        <汉字><space><comma-separated toneless pinyin readings>

    in the SAME order as the BIP-39 simplified-Chinese wordlist, so the line
    number equals the character's BIP-39 index. Heteronyms (多音字) are all
    indexed so a character is reachable by any of its readings, and ``ü``
    readings are stored as both ``v`` and ``u`` spellings.

    The index is tiny (~2k characters) and is built once and cached, so the
    linear prefix scans below are trivially cheap even on a Pi Zero.
    """

    _instance: "PinyinWordlist" = None
    RESOURCE_FILENAME = "zh_Hans_pinyin.txt"

    @classmethod
    def get_instance(cls) -> "PinyinWordlist":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        # (reading, char, bip39_index) for every reading of every wordlist char.
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
                    if reading:
                        self._entries.append((reading, char, index))

    def candidate_words(self, pinyin_prefix: str) -> List[str]:
        """Characters whose pinyin (any reading) starts with ``pinyin_prefix``.

        De-duplicated and ordered by BIP-39 index, which for the simplified-Chinese
        wordlist is roughly most-common-first.
        """
        if not pinyin_prefix:
            return []
        first_index_for_char = {}
        for reading, char, index in self._entries:
            if reading.startswith(pinyin_prefix) and char not in first_index_for_char:
                first_index_for_char[char] = index
        return [char for char, _ in sorted(first_index_for_char.items(), key=lambda kv: kv[1])]

    def next_letters(self, pinyin_prefix: str) -> List[str]:
        """The set of letters that can validly follow ``pinyin_prefix``.

        i.e. for every reading that starts with the prefix and is longer than it,
        the next character of that reading. Used to gray out impossible keys.
        """
        letters = []
        seen = set()
        prefix_len = len(pinyin_prefix)
        for reading, char, index in self._entries:
            if reading.startswith(pinyin_prefix) and len(reading) > prefix_len:
                letter = reading[prefix_len]
                if letter not in seen:
                    seen.add(letter)
                    letters.append(letter)
        return letters
