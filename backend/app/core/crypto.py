"""Cryptographic primitives: AES-256-GCM envelope encryption, Argon2id passwords, API keys."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_VERSION = "v1"
_password_hasher = PasswordHasher()  # Argon2id with library-recommended parameters
# Pre-computed hash used to equalise timing when a username does not exist.
_DUMMY_HASH = _password_hasher.hash("dummy-password-for-timing")


class Encryptor:
    """AES-256-GCM with a random 96-bit nonce. Output: ``v1:<b64(nonce|ciphertext)>``.

    ``associated_data`` binds a ciphertext to its context (e.g. tenant id + record id), so a
    ciphertext copied into another record or tenant fails to decrypt.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        self._aead = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated_data: str) -> str:
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, plaintext, associated_data.encode())
        return f"{KEY_VERSION}:" + base64.urlsafe_b64encode(nonce + ct).decode()

    def decrypt(self, token: str, associated_data: str) -> bytes:
        version, _, payload = token.partition(":")
        if version != KEY_VERSION:
            raise ValueError("Unsupported key version")
        raw = base64.urlsafe_b64decode(payload)
        return self._aead.decrypt(raw[:12], raw[12:], associated_data.encode())


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _password_hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _password_hasher.check_needs_rehash(password_hash)


@dataclass(frozen=True)
class GeneratedApiKey:
    key_prefix: str  # public, indexed: mgw_live_<public-id>
    secret: str  # full key shown once: <prefix>_<random>
    secret_hash: str


API_KEY_SCHEME = "mgw"


def generate_api_key(pepper: str, env: str = "live") -> GeneratedApiKey:
    public_id = secrets.token_hex(8)
    random_part = secrets.token_urlsafe(32).replace("_", "x").replace("-", "y")
    prefix = f"{API_KEY_SCHEME}_{env}_{public_id}"
    full = f"{prefix}_{random_part}"
    return GeneratedApiKey(key_prefix=prefix, secret=full, secret_hash=hash_api_key(full, pepper))


def hash_api_key(full_key: str, pepper: str) -> str:
    """HMAC-SHA256 with a server-side pepper. API keys are high-entropy, so a fast keyed hash is
    appropriate (no need for a slow password KDF) and allows constant-time verification."""
    return hmac.new(pepper.encode(), full_key.encode(), hashlib.sha256).hexdigest()


def split_api_key(full_key: str) -> str | None:
    """Return the public prefix of a well-formed key, or None."""
    parts = full_key.split("_")
    if len(parts) != 4 or parts[0] != API_KEY_SCHEME or parts[1] not in ("live", "test"):
        return None
    if not (len(parts[2]) == 16 and all(c in "0123456789abcdef" for c in parts[2])):
        return None
    if not (20 <= len(parts[3]) <= 128):
        return None
    return "_".join(parts[:3])


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)
