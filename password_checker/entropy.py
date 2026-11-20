import math
import string


def calculate_charset_size(password: str) -> int:
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += 32
    if any(c.isspace() for c in password):
        pool += 1
    return pool


def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0
    pool = calculate_charset_size(password)
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 2)


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return "Instant (< 1 second)"
    intervals = [
        ("centuries", 60 * 60 * 24 * 365 * 100),
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, count in intervals:
        value = seconds / count
        if value >= 1:
            if value > 1_000_000 and name == "centuries":
                return "Millions of centuries"
            return f"{value:,.1f} {name}"
    return "< 1 second"


def simulate_hash_cracking(entropy_bits: float) -> dict:
    """
    Estimates average brute-force time (50% of keyspace: 2^(H-1))
    assuming a modern high-end GPU cracking rig (e.g., 8x RTX 4090).
    """
    if entropy_bits <= 0:
        return {}

    # Average guesses needed = 2^(H - 1)
    # Cap exponent to prevent float overflow
    avg_guesses = 2 ** min(entropy_bits - 1, 256)

    # Approximate hashes per second on a high-end GPU cluster
    hash_rates = {
        "MD5 (Unsalted - Broken)": 100_000_000_000,       # 100 GH/s
        "SHA-1 (Unsalted - Weak)": 40_000_000_000,        # 40 GH/s
        "bcrypt (Cost 12 - Strong)": 100_000,             # 100 kH/s
        "Argon2id (Memory-Hard - Best)": 10_000,          # 10 kH/s
    }

    return {
        algo: format_duration(avg_guesses / rate)
        for algo, rate in hash_rates.items()
    }