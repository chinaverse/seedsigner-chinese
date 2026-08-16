import logging
import os
import unicodedata
import hashlib
import hmac

from binascii import hexlify
from embit import bip39, bip32, bip85
from embit.networks import NETWORKS
from typing import List

from seedsigner.models.settings import SettingsConstants

logger = logging.getLogger(__name__)


class InvalidSeedException(Exception):
    pass



class Seed:
    # Cache for BIP-39 wordlists that are bundled as resource files (i.e. anything
    # embit doesn't ship itself). Keyed by wordlist_language_code.
    _resource_wordlist_cache: dict = {}

    def __init__(self,
                 mnemonic: List[str] = None,
                 passphrase: str = "",
                 wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> None:
        self._wordlist_language_code = wordlist_language_code

        if not mnemonic:
            raise Exception("Must initialize a Seed with a mnemonic List[str]")
        self._mnemonic: List[str] = unicodedata.normalize("NFKD", " ".join(mnemonic).strip()).split()

        self._passphrase: str = ""
        self.set_passphrase(passphrase, regenerate_seed=False)

        self.seed_bytes: bytes = None
        self._generate_seed()


    @staticmethod
    def get_wordlist(wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> List[str]:
        if wordlist_language_code == SettingsConstants.WORDLIST_LANGUAGE__ENGLISH:
            # embit ships the English wordlist
            return bip39.WORDLIST
        elif wordlist_language_code == SettingsConstants.WORDLIST_LANGUAGE__CHINESE_SIMPLIFIED:
            return Seed._get_resource_wordlist(wordlist_language_code, "chinese_simplified.txt")
        else:
            raise Exception(f"Unrecognized wordlist_language_code {wordlist_language_code}")


    @staticmethod
    def _get_resource_wordlist(wordlist_language_code: str, filename: str) -> List[str]:
        """Load (and cache) a bundled BIP-39 wordlist resource file.

        The file must contain exactly 2048 words in canonical BIP-39 index order,
        one word per line (utf-8).
        """
        if wordlist_language_code not in Seed._resource_wordlist_cache:
            wordlist_path = os.path.join(
                os.path.dirname(__file__), "..", "resources", "wordlists", filename
            )
            with open(wordlist_path, encoding="utf-8") as wordlist_file:
                words = [line.strip() for line in wordlist_file if line.strip()]
            if len(words) != 2048:
                raise Exception(
                    f"Invalid BIP-39 wordlist '{filename}': expected 2048 words, got {len(words)}"
                )
            Seed._resource_wordlist_cache[wordlist_language_code] = words
        return Seed._resource_wordlist_cache[wordlist_language_code]


    def _generate_seed(self):
        try:
            derivation_mnemonic, derivation_wordlist = self._get_derivation_mnemonic()
            self.seed_bytes = bip39.mnemonic_to_seed(derivation_mnemonic, password=self._passphrase, wordlist=derivation_wordlist)
        except Exception as e:
            logger.info(repr(e), exc_info=True)
            raise InvalidSeedException(repr(e))


    def _get_derivation_mnemonic(self) -> tuple:
        """Returns (mnemonic_str, wordlist) used for KEY DERIVATION (PBKDF2 + checksum).

        For simplified Chinese this device DELIBERATELY derives the standard ENGLISH
        BIP-39 wallet for the same word indices: the Chinese characters are an input /
        display alias only, so a seed entered as Chinese yields the very same wallet as
        the corresponding English words at the same indices.

        IMPORTANT: the portable backup of such a wallet is therefore the ENGLISH words
        (or equivalently the SeedQR / word indices) — NOT the handwritten Chinese
        characters, which a standard wallet would interpret as a different (Chinese-seed)
        wallet.
        """
        if self._wordlist_language_code == SettingsConstants.WORDLIST_LANGUAGE__CHINESE_SIMPLIFIED:
            chinese_wordlist = Seed.get_wordlist(SettingsConstants.WORDLIST_LANGUAGE__CHINESE_SIMPLIFIED)
            english_wordlist = bip39.WORDLIST
            english_words = [english_wordlist[chinese_wordlist.index(word)] for word in self._mnemonic]
            return " ".join(english_words), english_wordlist
        return self.mnemonic_str, self.wordlist


    @property
    def mnemonic_str(self) -> str:
        return " ".join(self._mnemonic)


    @property
    def mnemonic_list(self) -> List[str]:
        return self._mnemonic


    @property
    def wordlist_language_code(self) -> str:
        return self._wordlist_language_code


    @property
    def mnemonic_indexes(self) -> List[int]:
        """The seed's BIP-39 word indices: its language-independent identity.

        Every supported wordlist addresses the same 2048 indices, so these are what
        stay fixed when the same seed is expressed in a different language (and are
        also exactly what a SeedQR encodes).
        """
        wordlist = self.wordlist
        return [wordlist.index(word) for word in self._mnemonic]


    @property
    def is_wordlist_language_switchable(self) -> bool:
        """Whether this seed's words may be re-rendered in a different BIP-39 wordlist.

        True for standard BIP-39 seeds, whose words are just a rendering of the
        underlying word indices. Subclasses that derive from the literal mnemonic
        string rather than from indices must override this (see `ElectrumSeed`).
        """
        return True


    @property
    def display_wordlist_language_code(self) -> str:
        """The wordlist language the seed's words should be SHOWN in.

        Follows the user's current wordlist language setting, so switching that
        setting re-renders seeds that are already loaded instead of leaving them
        stuck in whichever language they happened to be created or scanned in.
        """
        if not self.is_wordlist_language_switchable:
            return self._wordlist_language_code

        # Imported here (rather than at module level) to keep `Seed` importable
        # without pulling in the Settings singleton.
        from seedsigner.models.settings import Settings
        return Settings.get_instance().get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)


    def get_mnemonic_in_language(self, wordlist_language_code: str) -> List[str]:
        """This same seed's words, expressed in the given BIP-39 wordlist.

        Purely a change of rendering: the word indices — and therefore the wallet
        this seed derives — are untouched.
        """
        if wordlist_language_code == self._wordlist_language_code:
            return list(self._mnemonic)

        target_wordlist = Seed.get_wordlist(wordlist_language_code)
        return [target_wordlist[index] for index in self.mnemonic_indexes]


    @property
    def mnemonic_display_str(self) -> str:
        return unicodedata.normalize("NFC", " ".join(self.get_mnemonic_in_language(self.display_wordlist_language_code)))


    @property
    def mnemonic_display_list(self) -> List[str]:
        return unicodedata.normalize("NFC", " ".join(self.get_mnemonic_in_language(self.display_wordlist_language_code))).split()


    @property
    def has_passphrase(self):
        return self._passphrase != ""


    @property
    def passphrase(self):
        return self._passphrase
        

    @property
    def passphrase_display(self):
        return unicodedata.normalize("NFC", self._passphrase)


    def set_passphrase(self, passphrase: str, regenerate_seed: bool = True):
        if passphrase:
            self._passphrase = unicodedata.normalize("NFKD", passphrase)
        else:
            # Passphrase must always have a string value, even if it's just the empty
            # string.
            self._passphrase = ""

        if regenerate_seed:
            # Regenerate the internal seed since passphrase changes the result
            self._generate_seed()


    @property
    def wordlist(self) -> List[str]:
        return Seed.get_wordlist(self.wordlist_language_code)


    def set_wordlist_language_code(self, language_code: str):
        self._wordlist_language_code = language_code
        # The wordlist is used to validate the mnemonic during seed derivation, so
        # re-derive against the newly-selected language.
        self._generate_seed()


    @property
    def script_override(self) -> str:
        return None


    def derivation_override(self, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        return None


    def detect_version(self, derivation_path: str, network: str = SettingsConstants.MAINNET, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
        return bip32.detect_version(derivation_path, default="xpub", network=embit_network)


    @property
    def passphrase_label(self) -> str:
        return SettingsConstants.LABEL__BIP39_PASSPHRASE


    @property
    def seedqr_supported(self) -> bool:
        return True


    @property
    def bip85_supported(self) -> bool:
        return True


    def get_fingerprint(self, network: str = SettingsConstants.MAINNET) -> str:
        root = bip32.HDKey.from_seed(self.seed_bytes, version=NETWORKS[SettingsConstants.map_network_to_embit(network)]["xprv"])
        return hexlify(root.child(0).fingerprint).decode('utf-8')


    def get_xpub(self, wallet_path: str = '/', network: str = SettingsConstants.MAINNET):
        # Import here to avoid slow startup times; takes 1.35s to import the first time
        from seedsigner.helpers import embit_utils
        return embit_utils.get_xpub(seed_bytes=self.seed_bytes, derivation_path=wallet_path, embit_network=SettingsConstants.map_network_to_embit(network))


    def get_bip85_child_mnemonic(self, bip85_index: int, bip85_num_words: int, network: str = SettingsConstants.MAINNET):
        """Derives the seed's nth BIP-85 child mnemonic"""
        root = bip32.HDKey.from_seed(self.seed_bytes, version=NETWORKS[SettingsConstants.map_network_to_embit(network)]["xprv"])

        # TODO: Support other BIP-39 wordlist languages!
        return bip85.derive_mnemonic(root, bip85_num_words, bip85_index)
        

    ### override operators    
    def __eq__(self, other):
        if isinstance(other, Seed):
            return self.seed_bytes == other.seed_bytes
        return False



class ElectrumSeed(Seed):

    def _generate_seed(self):
        if len(self._mnemonic) != 12:
            raise InvalidSeedException(f"Unsupported Electrum seed length: {len(self._mnemonic)}")

        s = hmac.digest(b"Seed version", self.mnemonic_str.encode('utf8'), hashlib.sha512).hex()
        prefix = s[0:3]

        # only support Electrum Segwit version for now
        if SettingsConstants.ELECTRUM_SEED_SEGWIT == prefix:
            self.seed_bytes=hashlib.pbkdf2_hmac('sha512', self.mnemonic_str.encode('utf-8'), b'electrum' + self._passphrase.encode('utf-8'), iterations = SettingsConstants.ELECTRUM_PBKDF2_ROUNDS)

        else:
            raise InvalidSeedException(f"Unsupported Electrum seed format: {prefix}")


    def set_passphrase(self, passphrase: str, regenerate_seed: bool = True):
        if passphrase:
            self._passphrase = ElectrumSeed.normalize_electrum_passphrase(passphrase)
        else:
            # Passphrase must always have a string value, even if it's just the empty
            # string.
            self._passphrase = ""

        if regenerate_seed:
            # Regenerate the internal seed since passphrase changes the result
            self._generate_seed()


    @staticmethod
    def normalize_electrum_passphrase(passphrase : str) -> str:
        passphrase = unicodedata.normalize('NFKD', passphrase)
        # lower
        passphrase = passphrase.lower()
        # normalize whitespaces
        passphrase = u' '.join(passphrase.split())
        return passphrase


    @property
    def is_wordlist_language_switchable(self) -> bool:
        """Electrum seeds derive from the literal mnemonic STRING, not from BIP-39
        word indices, so their words can't be re-rendered in another wordlist without
        misrepresenting what the actual backup is."""
        return False


    @property
    def script_override(self) -> str:
        return SettingsConstants.NATIVE_SEGWIT


    def derivation_override(self, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        return "m/0h" if sig_type == SettingsConstants.SINGLE_SIG else "m/1h"


    def detect_version(self, derivation_path: str, network: str = SettingsConstants.MAINNET, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
        return embit_network["zpub"] if sig_type == SettingsConstants.SINGLE_SIG else embit_network["Zpub"]


    @property
    def passphrase_label(self) -> str:
        return SettingsConstants.LABEL__CUSTOM_EXTENSION


    @property
    def seedqr_supported(self) -> bool:
        return False


    @property
    def bip85_supported(self) -> bool:
        return False
