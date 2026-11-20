import hashlib
import requests

HIBP_API_URL = "https://api.pwnedpasswords.com/range/{}"


def check_hibp_breach(password: str) -> dict:
    """
    Hashes password with SHA-1 locally, sends only the 5-char prefix to HIBP,
    and checks the returned suffixes in memory.
    """
    if not password:
        return {"breached": False, "count": 0, "error": None}

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        response = requests.get(
            HIBP_API_URL.format(prefix),
            headers={"Add-Padding": "true", "User-Agent": "SmartPasswordAnalyzer-BTech"},
            timeout=5,
        )
        response.raise_for_status()
    except requests.RequestException:
        return {
            "breached": False,
            "count": 0,
            "error": "Could not reach HIBP API. Check internet connection.",
        }

    for line in response.text.splitlines():
        if ":" not in line:
            continue
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return {"breached": True, "count": int(count), "error": None}

    return {"breached": False, "count": 0, "error": None}