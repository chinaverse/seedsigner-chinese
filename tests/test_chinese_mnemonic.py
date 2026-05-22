"""
Correctness tests for the simplified-Chinese BIP-39 wordlist + pinyin input support.

The security-critical assertion here is that SeedSigner derives exactly the same
seed bytes (and therefore the same keys) as an INDEPENDENT reference implementation
(Trezor's `mnemonic` library) for the same Chinese mnemonic. If this ever diverges,
funds restored on SeedSigner would not match other wallets.
"""
# Set up the hardware mocks before importing any seedsigner modules.
from base import BaseTest

import pytest
from mnemonic import Mnemonic

from seedsigner.helpers import mnemonic_generation
from seedsigner.helpers.pinyin import PinyinWordlist
from seedsigner.models.decode_qr import DecodeQRStatus, SeedQrDecoder
from seedsigner.models.encode_qr import CompactSeedQrEncoder, SeedQrEncoder
from seedsigner.models.qr_type import QRType
from seedsigner.models.seed import Seed, InvalidSeedException
from seedsigner.models.settings import SettingsConstants


ZH = SettingsConstants.WORDLIST_LANGUAGE__CHINESE_SIMPLIFIED

# A few entropy values to derive valid 12- and 24-word Chinese mnemonics from.
ENTROPIES = [
    bytes(16),                                  # all zeros, 12 words
    bytes.fromhex("ffffffffffffffffffffffffffffffff"),
    bytes.fromhex("7f8e2c1a0b6d4f3e9a1c5d7b2e4f6081"),
    bytes(32),                                  # all zeros, 24 words
    bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
]


def english_equivalent_str(zh_words):
    """English BIP-39 mnemonic string at the same indices as the Chinese words.

    This device DERIVES the wallet from this English equivalent; the Chinese
    characters are only an input/display alias.
    """
    zh = Seed.get_wordlist(ZH)
    en = Mnemonic("english").wordlist
    return " ".join(en[zh.index(w)] for w in zh_words)


class TestChineseWordlist(BaseTest):
    def test_wordlist_loads_and_matches_reference(self):
        wordlist = Seed.get_wordlist(ZH)
        assert len(wordlist) == 2048
        assert all(len(w) == 1 for w in wordlist)  # each BIP-39 zh word is one char
        # Must exactly match the independent reference implementation, in order.
        assert wordlist == Mnemonic("chinese_simplified").wordlist

    def test_wordlist_is_cached(self):
        assert Seed.get_wordlist(ZH) is Seed.get_wordlist(ZH)


class TestChineseSeedDerivation(BaseTest):
    """This device intentionally derives the standard ENGLISH wallet for the same
    word indices; the Chinese characters are an input/display alias only."""

    @pytest.mark.parametrize("entropy", ENTROPIES)
    def test_chinese_input_derives_english_wallet(self, entropy):
        zh_words = Mnemonic("chinese_simplified").to_mnemonic(entropy).split()
        seed = Seed(zh_words, wordlist_language_code=ZH)

        # Derives the ENGLISH-words wallet at the same indices...
        en_str = english_equivalent_str(zh_words)
        assert en_str == Mnemonic("english").to_mnemonic(entropy)  # sanity
        assert seed.seed_bytes == Mnemonic.to_seed(en_str)
        # ...and is byte-identical to constructing from the English words directly.
        assert seed.seed_bytes == Seed(en_str.split(), wordlist_language_code="en").seed_bytes
        # ...while the mnemonic still DISPLAYS as the Chinese characters.
        assert seed.mnemonic_display_list == zh_words

    def test_fingerprint_matches_english_wallet(self):
        for entropy in ENTROPIES:
            zh_words = Mnemonic("chinese_simplified").to_mnemonic(entropy).split()
            en_words = Mnemonic("english").to_mnemonic(entropy).split()
            zh_fp = Seed(zh_words, wordlist_language_code=ZH).get_fingerprint()
            en_fp = Seed(en_words, wordlist_language_code="en").get_fingerprint()
            assert zh_fp == en_fp

    def test_with_passphrase_matches_english_wallet(self):
        zh_words = Mnemonic("chinese_simplified").to_mnemonic(ENTROPIES[2]).split()
        passphrase = "correct horse battery staple"
        seed = Seed(zh_words, passphrase=passphrase, wordlist_language_code=ZH)
        assert seed.seed_bytes == Mnemonic.to_seed(english_equivalent_str(zh_words), passphrase=passphrase)

    def test_invalid_checksum_is_rejected(self):
        # Swap the first word for another valid word -> checksum should fail.
        wordlist = Seed.get_wordlist(ZH)
        phrase = Mnemonic("chinese_simplified").to_mnemonic(bytes(16)).split()
        phrase[0] = wordlist[(wordlist.index(phrase[0]) + 1) % 2048]
        with pytest.raises(InvalidSeedException):
            Seed(phrase, wordlist_language_code=ZH)

    def test_set_wordlist_language_code(self):
        zh_words = Mnemonic("chinese_simplified").to_mnemonic(ENTROPIES[0]).split()
        seed = Seed(zh_words, wordlist_language_code=ZH)
        seed.set_wordlist_language_code(ZH)
        assert seed.seed_bytes == Mnemonic.to_seed(english_equivalent_str(zh_words))


class TestChineseMnemonicGeneration(BaseTest):
    def test_generate_from_bytes_produces_valid_chinese(self):
        words = mnemonic_generation.generate_mnemonic_from_bytes(ENTROPIES[2], wordlist_language_code=ZH)
        assert len(words) == 12
        wordlist = Seed.get_wordlist(ZH)
        assert all(w in wordlist for w in words)
        # Should construct a valid Seed (checksum passes).
        seed = Seed(words, wordlist_language_code=ZH)
        assert len(seed.seed_bytes) == 64

    def test_calculate_checksum_returns_chinese_final_word(self):
        # Regression (Tools -> Calc 12th/24th word): calculate_checksum re-encoded the
        # computed mnemonic with the default ENGLISH wordlist, so the final word came
        # back as an English word that then failed lookup in the Chinese wordlist.
        wordlist = Seed.get_wordlist(ZH)
        for entropy in (ENTROPIES[2], ENTROPIES[4]):  # 12- and 24-word
            full = Mnemonic("chinese_simplified").to_mnemonic(entropy).split()
            partial = full[:-1]  # 11 or 23 words
            result = mnemonic_generation.calculate_checksum(list(partial), wordlist_language_code=ZH)
            assert len(result) == len(full)
            bad = [w for w in result if w not in wordlist]
            assert not bad, f"calculate_checksum returned non-Chinese words: {bad}"
            Seed(result, wordlist_language_code=ZH)  # must be a valid mnemonic


class TestChineseSeedQR(BaseTest):
    """SeedQR round-trips for Chinese (encoder -> decoder, bypassing pyzbar image extraction)."""

    def _roundtrip(self, entropy, qr_type):
        words = Mnemonic("chinese_simplified").to_mnemonic(entropy).split()
        if qr_type == QRType.SEED__SEEDQR:
            data = SeedQrEncoder(mnemonic=words, wordlist_language_code=ZH).next_part()
        else:
            data = CompactSeedQrEncoder(mnemonic=words, wordlist_language_code=ZH).next_part()
        decoder = SeedQrDecoder(wordlist_language_code=ZH)
        assert decoder.add(data, qr_type=qr_type) == DecodeQRStatus.COMPLETE
        assert decoder.seed_phrase == words

    @pytest.mark.parametrize("entropy", [ENTROPIES[2], ENTROPIES[4]])  # 12- and 24-word
    def test_numeric_seedqr_roundtrip(self, entropy):
        self._roundtrip(entropy, QRType.SEED__SEEDQR)

    @pytest.mark.parametrize("entropy", [ENTROPIES[2], ENTROPIES[4]])  # 12- and 24-word
    def test_compact_seedqr_roundtrip(self, entropy):
        # Exercises the CompactSeedQR decode path that must reconstruct using the
        # Chinese wordlist (not embit's default English).
        self._roundtrip(entropy, QRType.SEED__COMPACTSEEDQR)


class TestChinesePendingSeedStorage(BaseTest):
    """Regression: the entry/restore finalize path must build the Seed with the
    selected wordlist language, not the default English (which rejected valid
    Chinese mnemonics as 'Invalid Mnemonic')."""

    def _enter(self, num_words, entropy):
        from seedsigner.models.seed_storage import SeedStorage
        self.settings.set_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE, ZH)
        words = Mnemonic("chinese_simplified").to_mnemonic(entropy).split()
        storage = SeedStorage()
        storage.init_pending_mnemonic(num_words=num_words)
        for i, w in enumerate(words):
            storage.update_pending_mnemonic(w, i)
        return storage, words

    def test_pending_chinese_mnemonic_finalizes(self):
        storage, words = self._enter(12, ENTROPIES[2])
        # Must NOT raise InvalidSeedException
        storage.convert_pending_mnemonic_to_pending_seed()
        seed = storage.get_pending_seed()
        assert seed is not None
        assert seed.wordlist_language_code == ZH
        # Chinese input derives the English-words wallet at the same indices.
        assert seed.seed_bytes == Mnemonic.to_seed(english_equivalent_str(words))

    def test_pending_chinese_fingerprint_available(self):
        storage, _ = self._enter(24, ENTROPIES[4])
        assert storage.get_pending_mnemonic_fingerprint() is not None

    def test_validate_chinese_mnemonic(self):
        from seedsigner.models.seed_storage import SeedStorage
        words = Mnemonic("chinese_simplified").to_mnemonic(ENTROPIES[0]).split()
        assert SeedStorage().validate_mnemonic(words, wordlist_language_code=ZH) is True


class TestChineseEntryRouting(BaseTest):
    """Both normal seed entry AND the Tools 'Calc 12th/24th word' flow go through
    SeedMnemonicEntryView, so both must route to the pinyin screen when the
    wordlist language is Chinese."""

    def _captured_screen_class(self, is_calc_final_word: bool):
        from unittest.mock import patch
        from seedsigner.views import seed_views
        from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
        self.settings.set_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE, ZH)
        self.controller.storage.init_pending_mnemonic(num_words=12)
        view = seed_views.SeedMnemonicEntryView(cur_word_index=0, is_calc_final_word=is_calc_final_word)
        captured = {}

        def fake_run_screen(screen_class, **kwargs):
            captured["cls"] = screen_class
            return RET_CODE__BACK_BUTTON

        with patch.object(view, "run_screen", side_effect=fake_run_screen):
            view.run()
        return captured.get("cls")

    def test_normal_entry_uses_pinyin_for_chinese(self):
        from seedsigner.gui.screens import seed_screens
        assert self._captured_screen_class(False) is seed_screens.SeedMnemonicPinyinEntryScreen

    def test_calc_final_word_entry_uses_pinyin_for_chinese(self):
        from seedsigner.gui.screens import seed_screens
        assert self._captured_screen_class(True) is seed_screens.SeedMnemonicPinyinEntryScreen


class TestPinyinWordlist(BaseTest):
    def setup_method(self):
        super().setup_method()
        self.pinyin = PinyinWordlist.get_instance()
        self.wordlist = Seed.get_wordlist(ZH)

    def test_candidates_are_all_valid_bip39_words(self):
        for prefix in ["a", "sh", "shi", "zhong", "lv", "nv"]:
            for char in self.pinyin.candidate_words(prefix):
                assert char in self.wordlist

    def test_full_syllable_candidates_tone_ordered(self):
        # "shi" surfaces 是/时/十/使 etc., ordered by tone (1->4), not frequency.
        candidates = self.pinyin.candidate_words("shi")
        for c in ["是", "时", "十", "使"]:
            assert c in candidates
        # 时/十 are shi2 (tone 2) -> before 使 shi3 (tone 3) -> before 是 shi4 (tone 4)
        assert candidates.index("十") < candidates.index("使") < candidates.index("是")
        assert candidates.index("时") < candidates.index("是")

    def test_heteronyms_reachable_by_each_reading(self):
        # 行 reads xing / hang / heng -> reachable by all.
        assert "行" in self.pinyin.candidate_words("xing")
        assert "行" in self.pinyin.candidate_words("hang")

    def test_u_umlaut_typed_as_v(self):
        # Standard Chinese input: ü is typed as "v". So 女 (nü) -> "nv", 绿 (lü) -> "lv".
        assert "女" in self.pinyin.candidate_words("nv")
        assert "绿" in self.pinyin.candidate_words("lv")
        # "nu" is a different syllable (奴/努/怒) and must NOT surface 女.
        assert "女" not in self.pinyin.candidate_words("nu")

    def test_next_letters_restricts_keyboard(self):
        # After a complete syllable with no longer reading, no further letters.
        assert self.pinyin.next_letters("shuang") == []
        # "sh" can continue to several vowels.
        nexts = set(self.pinyin.next_letters("sh"))
        assert {"a", "e", "i", "u"}.issubset(nexts)

    def test_empty_prefix_yields_no_candidates(self):
        assert self.pinyin.candidate_words("") == []
