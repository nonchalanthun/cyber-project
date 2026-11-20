import os
import secrets
import string

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
WORDLIST_PATH = os.path.join(DATA_DIR, "eff_wordlist.txt")

FALLBACK_WORDS = [
    "correct", "horse", "battery", "staple", "quantum", "cipher", "nebula",
    "falcon", "velvet", "glacier", "orbit", "prism", "summit", "anchor",
    "cobalt", "horizon", "lantern", "meadow", "quartz", "timber"
]


def _load_wordlist() -> list:
    if not os.path.exists(WORDLIST_PATH):
        return FALLBACK_WORDS
    words = []
    with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()
            if parts:
                words.append(parts[-1]) 
    return words or FALLBACK_WORDS


WORDLIST = _load_wordlist()


def generate_random_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    length = max(8, min(length, 128))
    char_pools = []
    required_chars = []

    if use_lower:
        char_pools.append(string.ascii_lowercase)
        required_chars.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        char_pools.append(string.ascii_uppercase)
        required_chars.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        char_pools.append(string.digits)
        required_chars.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        char_pools.append(symbols)
        required_chars.append(secrets.choice(symbols))

    if not char_pools:
        char_pools.append(string.ascii_letters + string.digits)

    all_chars = "".join(char_pools)
    remaining_length = length - len(required_chars)
    password_chars = required_chars + [secrets.choice(all_chars) for _ in range(remaining_length)]

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def generate_passphrase(num_words: int = 5, separator: str = "-", capitalize: bool = True) -> str:
    num_words = max(3, min(num_words, 10))
    chosen = [secrets.choice(WORDLIST) for _ in range(num_words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    return separator.join(chosen)
