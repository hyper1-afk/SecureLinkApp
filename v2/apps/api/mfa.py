"""TOTP and recovery-code helpers for account MFA."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

from cryptography.fernet import Fernet, InvalidToken


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret: str, timestamp: int | None = None) -> str:
    moment = int(time.time() if timestamp is None else timestamp)
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = moment // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"


def verify_totp(secret: str, code: str, timestamp: int | None = None) -> bool:
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return False
    moment = int(time.time() if timestamp is None else timestamp)
    return any(
        hmac.compare_digest(totp_code(secret, moment + delta * 30), code)
        for delta in (-1, 0, 1)
    )


def encrypt_secret(secret: str, key: str) -> bytes:
    return Fernet(key.encode("ascii")).encrypt(secret.encode("ascii"))


def decrypt_secret(ciphertext: bytes, key: str) -> str:
    try:
        return Fernet(key.encode("ascii")).decrypt(ciphertext).decode("ascii")
    except (InvalidToken, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("MFA secret cannot be decrypted") from exc


def new_recovery_codes(count: int = 10) -> list[str]:
    return [secrets.token_hex(12).upper() for _ in range(count)]


def recovery_code_hash(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").strip().upper().encode("ascii")).hexdigest()


def recovery_code_matches(code: str, expected_hash: str) -> bool:
    try:
        candidate = recovery_code_hash(code)
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(candidate, expected_hash)
