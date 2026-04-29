import secrets
import string


def generate_strong_password(length: int = 16, include_uppercase: bool = True, include_lowercase: bool = True, include_digits: bool = True, include_symbols: bool = True):
    length = int(length)
    if length < 8:
        return {"found": False, "status": "Password length must be at least 8"}

    selected_sets = []
    if include_uppercase:
        selected_sets.append(string.ascii_uppercase)
    if include_lowercase:
        selected_sets.append(string.ascii_lowercase)
    if include_digits:
        selected_sets.append(string.digits)
    if include_symbols:
        selected_sets.append("!@#$%^&*()-_=+[]{};:,.?/\\|~")

    if not selected_sets:
        return {"found": False, "status": "Select at least one character set"}

    if length < len(selected_sets):
        return {"found": False, "status": "Length is too short for selected character sets"}

    mandatory_chars = [secrets.choice(charset) for charset in selected_sets]
    pool = "".join(selected_sets)
    remaining = [secrets.choice(pool) for _ in range(length - len(mandatory_chars))]
    all_chars = mandatory_chars + remaining
    secrets.SystemRandom().shuffle(all_chars)
    password = "".join(all_chars)

    return {
        "found": True,
        "password": password,
        "length": length,
        "settings": {
            "include_uppercase": include_uppercase,
            "include_lowercase": include_lowercase,
            "include_digits": include_digits,
            "include_symbols": include_symbols
        }
    }
