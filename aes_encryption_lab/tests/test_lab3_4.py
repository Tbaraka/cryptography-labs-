"""
tests/test_lab3_4.py
Unit tests for Lab 3.4 — PBKDF2 Password-Based Encryption
"""

import pytest
import base64
from src.lab3_4_pbkdf2 import (
    encrypt_with_password,
    decrypt_with_password,
    derive_key,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    KEY_SIZE,
    KDF_ITERATIONS,
)


class TestKeyDerivation:

    def test_derive_key_returns_correct_length(self):
        """Derived key must be exactly 32 bytes for AES-256."""
        key = derive_key(b"password", b"saltsaltsaltsalt")
        assert len(key) == KEY_SIZE

    def test_same_inputs_produce_same_key(self):
        """PBKDF2 is deterministic — same password + salt always gives same key."""
        salt = b"saltsaltsaltsalt"
        key1 = derive_key(b"password", salt)
        key2 = derive_key(b"password", salt)
        assert key1 == key2

    def test_different_salts_produce_different_keys(self):
        """Same password with different salts must produce different keys."""
        key1 = derive_key(b"password", b"saltsaltsaltsalt")
        key2 = derive_key(b"password", b"differentsalt123")
        assert key1 != key2

    def test_different_passwords_produce_different_keys(self):
        """Different passwords with same salt must produce different keys."""
        salt = b"saltsaltsaltsalt"
        key1 = derive_key(b"password1", salt)
        key2 = derive_key(b"password2", salt)
        assert key1 != key2


class TestPasswordEncryption:

    def test_roundtrip_standard_message(self):
        """Encrypt then decrypt returns original plaintext."""
        plaintext = b"Sensitive data"
        password  = b"strongpassword"
        assert decrypt_with_password(
            encrypt_with_password(plaintext, password), password
        ) == plaintext

    def test_roundtrip_empty_plaintext(self):
        """Empty plaintext encrypts and decrypts correctly."""
        assert decrypt_with_password(
            encrypt_with_password(b"", b"password"), b"password"
        ) == b""

    def test_unique_output_per_encryption(self):
        """Same password and plaintext produces different output each time."""
        enc1 = encrypt_with_password(b"message", b"password")
        enc2 = encrypt_with_password(b"message", b"password")
        assert enc1 != enc2

    def test_output_structure(self):
        """Encoded output contains correct number of bytes for each component."""
        plaintext = b"Test message"
        encoded   = encrypt_with_password(plaintext, b"password")
        raw       = base64.b64decode(encoded)

        # Minimum size: salt + nonce + tag + at least 1 byte ciphertext
        assert len(raw) >= SALT_SIZE + NONCE_SIZE + TAG_SIZE + len(plaintext)

    def test_wrong_password_rejected(self):
        """Decrypting with wrong password raises ValueError."""
        encrypted = encrypt_with_password(b"Secret", b"correctpassword")
        with pytest.raises(ValueError):
            decrypt_with_password(encrypted, b"wrongpassword")

    def test_empty_password_works(self):
        """Empty password is technically valid — derives a key like any other."""
        plaintext = b"Test"
        encrypted = encrypt_with_password(plaintext, b"")
        assert decrypt_with_password(encrypted, b"") == plaintext

    def test_unicode_password(self):
        """Non-ASCII passwords are handled correctly."""
        password  = "pässwörd".encode("utf-8")
        plaintext = b"Secret message"
        encrypted = encrypt_with_password(plaintext, password)
        assert decrypt_with_password(encrypted, password) == plaintext

    def test_tampered_ciphertext_rejected(self):
        """Modifying ciphertext after encryption raises ValueError."""
        import base64
        encoded = encrypt_with_password(b"Secret data", b"password")
        raw     = bytearray(base64.b64decode(encoded))

        # Flip a byte in the ciphertext region
        raw[SALT_SIZE + NONCE_SIZE + TAG_SIZE] ^= 0xFF
        tampered = base64.b64encode(bytes(raw)).decode()

        with pytest.raises(ValueError):
            decrypt_with_password(tampered, b"password")