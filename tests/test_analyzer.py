from password_checker.analyzer import analyze_password
from password_checker.entropy import calculate_entropy
from password_checker.generator import generate_random_password, generate_passphrase


def test_weak_common_password():
    result = analyze_password("qwerty123", check_breach=False)
    assert result["category"] == "Weak"
    assert "Keyboard walk" in result["patterns"]


def test_strong_passphrase():
    result = analyze_password("Quantum-Glacier-Lantern-Summit-42!", check_breach=False)
    assert result["category"] in ("Strong", "Very Strong")
    assert result["entropy_bits"] > 80


def test_entropy_calculation():
    # 8 lowercase chars = 8 * log2(26) ≈ 37.6 bits
    assert 37.0 < calculate_entropy("abcdefgh") < 38.0


def test_generators():
    pw = generate_random_password(length=20)
    assert len(pw) == 20
    phrase = generate_passphrase(num_words=4, separator="-")
    assert len(phrase.split("-")) == 4