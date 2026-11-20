def generate_suggestions(checks: dict, patterns: list, zxcvbn_feedback: dict, breached: bool) -> list:
    suggestions = []

    if breached:
        suggestions.append(
            "CRITICAL: This password appeared in a known data breach. Stop using it immediately."
        )

    if not checks["min_length_12"]:
        suggestions.append(
            "Increase length to at least 12–16 characters. Length is the single strongest defense against cracking."
        )

    if not (checks["has_upper"] and checks["has_lower"]):
        suggestions.append("Mix uppercase and lowercase letters naturally (or use a multi-word passphrase).")

    if not checks["has_digit"]:
        suggestions.append("Include numbers, avoiding predictable years or birthdates.")

    if not checks["has_symbol"]:
        suggestions.append("Add special symbols (e.g., !, @, #, %) to expand the character pool.")

    if "Repeated characters" in patterns:
        suggestions.append("Avoid repeating the same character consecutively (e.g., 'aaa' or '111').")

    if "Sequential pattern" in patterns or "Keyboard walk" in patterns:
        suggestions.append("Remove predictable sequences like '1234', 'abcd', or keyboard walks like 'qwerty'.")

    if "Date pattern" in patterns:
        suggestions.append("Avoid dates or years (e.g., 1999, 2024) as attackers test these first.")

    for tip in zxcvbn_feedback.get("suggestions", []):
        if tip not in suggestions:
            suggestions.append(tip)

    if not suggestions:
        suggestions.append("Strong password! Pair it with a password manager and Multi-Factor Authentication (MFA).")

    return suggestions