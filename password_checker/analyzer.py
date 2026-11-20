import os
import re
from zxcvbn import zxcvbn
from .entropy import calculate_entropy, simulate_hash_cracking
from .breach_check import check_hibp_breach
from .suggestions import generate_suggestions

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
COMMON_PASSWORDS_PATH = os.path.join(DATA_DIR, "common_passwords.txt")

KEYBOARD_WALKS = ["qwerty", "asdfgh", "zxcvbn", "qazwsx", "123456", "098765"]


def _load_common_passwords() -> set:
    if not os.path.exists(COMMON_PASSWORDS_PATH):
        return {"password", "123456", "qwerty", "admin", "letmein", "welcome"}
    with open(COMMON_PASSWORDS_PATH, "r", encoding="utf-8", errors="ignore") as f:
        return {line.strip().lower() for line in f if line.strip()}


COMMON_PASSWORDS = _load_common_passwords()


def detect_patterns(password: str) -> list:
    patterns = []
    lower_pw = password.lower()

    if re.search(r"(.)\1{2,}", password):
        patterns.append("Repeated characters")

    if re.search(r"(?:012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg)", lower_pw):
        patterns.append("Sequential pattern")

    if any(walk in lower_pw for walk in KEYBOARD_WALKS):
        patterns.append("Keyboard walk")

    if re.search(r"(19\d{2}|20\d{2}|\d{2}[-/]\d{2}[-/]\d{2,4})", password):
        patterns.append("Date pattern")

    if lower_pw in COMMON_PASSWORDS:
        patterns.append("Found in local common passwords list")

    return patterns


def analyze_password(password: str, check_breach: bool = False) -> dict:
    if not password:
        return {"error": "Password cannot be empty."}

    # 1. Requirement checks
    checks = {
        "min_length_8": len(password) >= 8,
        "min_length_12": len(password) >= 12,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_symbol": bool(re.search(r"[^A-Za-z0-9\s]", password)),
    }

    # 2. Pattern & common list detection
    patterns = detect_patterns(password)

    # 3. zxcvbn evaluation (truncate to 72 chars as zxcvbn recommends for performance)
    zx_result = zxcvbn(password[:72])
    zx_score = zx_result["score"]  # 0 to 4

    # 4. Entropy & Cracking Simulator
    entropy_bits = calculate_entropy(password)
    cracking_times = simulate_hash_cracking(entropy_bits)

    # 5. Breach check (k-Anonymity)
    breach_info = {"breached": False, "count": 0, "error": None}
    if check_breach:
        breach_info = check_hibp_breach(password)

    # 6. Final Strength Classification
    if breach_info["breached"] or "Found in local common passwords list" in patterns:
        category = "Weak"
        score_percent = 10
    elif zx_score <= 1 or entropy_bits < 40:
        category = "Weak"
        score_percent = 25
    elif zx_score == 2 or entropy_bits < 60:
        category = "Medium"
        score_percent = 55
    elif zx_score == 3 or entropy_bits < 80:
        category = "Strong"
        score_percent = 80
    else:
        category = "Very Strong"
        score_percent = 100

    # 7. Smart Suggestions
    suggestions = generate_suggestions(
        checks, patterns, zx_result.get("feedback", {}), breach_info["breached"]
    )

    # Notice: Raw password is NEVER included in the returned dictionary
    return {
        "length": len(password),
        "category": category,
        "score_percent": score_percent,
        "zxcvbn_score": zx_score,
        "entropy_bits": entropy_bits,
        "checks": checks,
        "patterns": patterns,
        "breach": breach_info,
        "cracking_times": cracking_times,
        "suggestions": suggestions,
        "disclaimer": (
            "Entropy and cracking-time estimates are theoretical approximations based on "
            "offline GPU brute-force rates. They do not guarantee absolute security."
        ),
    }