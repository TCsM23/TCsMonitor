"""Password login with a signed cookie, using only the standard library.

Set the TCSM_PASSWORD environment variable to turn it on. If it's empty, login is
disabled (handy while developing on your own PC).
"""
import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

PASSWORD = os.getenv("TCSM_PASSWORD", "")
COOKIE = "tcsm_session"
MAX_AGE = 30 * 86400  # stay logged in for 30 days
_SECRET_FILE = Path(__file__).resolve().parent.parent / "data" / "secret.key"


def _load_secret() -> bytes:
    """A random key generated once and kept in data/secret.key (never commit it)."""
    _SECRET_FILE.parent.mkdir(exist_ok=True)
    if not _SECRET_FILE.exists():
        _SECRET_FILE.write_bytes(secrets.token_bytes(32))
    return _SECRET_FILE.read_bytes()


# Mixing the password into the key means changing the password logs everyone out.
_KEY = _load_secret() + PASSWORD.encode()


def enabled() -> bool:
    return bool(PASSWORD)


def check_password(attempt: str) -> bool:
    return hmac.compare_digest(attempt.encode(), PASSWORD.encode())  # constant-time compare


def _sign(expires: str) -> str:
    return hmac.new(_KEY, expires.encode(), hashlib.sha256).hexdigest()


def make_token() -> str:
    expires = str(int(time.time()) + MAX_AGE)
    return f"{expires}.{_sign(expires)}"


def valid_token(token: str | None) -> bool:
    if not enabled():
        return True
    if not token or "." not in token:
        return False
    expires, sig = token.split(".", 1)
    return (expires.isdigit() and int(expires) > time.time()
            and hmac.compare_digest(sig, _sign(expires)))
