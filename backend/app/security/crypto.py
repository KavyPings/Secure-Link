"""SHA-256 integrity hashing and AES-256-GCM authenticated encryption (FR-20, FR-21, section 17).

Blob layout: nonce (12 bytes) || ciphertext || GCM tag (16 bytes).
The AAD binds a blob to its database record, so a blob copied onto another record fails to decrypt.
"""
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import config

NONCE_SIZE = 12
TAG_SIZE = 16
_key_cache = None

__all__ = ["sha256_hex", "encrypt", "decrypt", "load_key", "InvalidTag"]


def load_key() -> bytes:
    """32-byte master key kept in a file outside the database; created on first run."""
    global _key_cache
    if _key_cache is None:
        if not config.KEY_FILE.exists():
            config.KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
            config.KEY_FILE.write_bytes(AESGCM.generate_key(bit_length=256))
        _key_cache = config.KEY_FILE.read_bytes()
    return _key_cache


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encrypt(plaintext: bytes, aad: bytes, key: bytes | None = None) -> bytes:
    nonce = os.urandom(NONCE_SIZE)  # fresh nonce every time; never reused with the same key
    return nonce + AESGCM(key or load_key()).encrypt(nonce, plaintext, aad)


def decrypt(blob: bytes, aad: bytes, key: bytes | None = None) -> bytes:
    """Raises cryptography.exceptions.InvalidTag if the blob or AAD was modified."""
    nonce, body = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key or load_key()).decrypt(nonce, body, aad)
