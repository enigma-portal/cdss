"""Authenticated encryption for connector credentials using an external local key."""

from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


class SecretProtectionError(RuntimeError):
    pass


KEY_FILE = Path(__file__).resolve().parents[2] / "data" / "connector.key"


def _cipher():
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not KEY_FILE.exists():
        KEY_FILE.write_bytes(Fernet.generate_key())
    try:
        return Fernet(KEY_FILE.read_bytes().strip())
    except (ValueError, OSError) as error:
        raise SecretProtectionError("Connector encryption key is unavailable or invalid.") from error


def protect_secret(value):
    if not value:
        raise SecretProtectionError("Connector password cannot be empty.")
    return _cipher().encrypt(value.encode("utf-8"))


def unprotect_secret(value):
    try:
        return _cipher().decrypt(bytes(value)).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, OSError) as error:
        raise SecretProtectionError("Connector credential could not be decrypted.") from error
