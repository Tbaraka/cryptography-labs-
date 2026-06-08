"""
tests/test_lab3_2.py
Unit tests for Lab 3.2 — AES-GCM Authenticated Encryption
"""

import pytest
import base64
from Crypto.Random import get_random_bytes
from src.lab3_2_gcm import encrypt_gcm, decrypt_gcm, NONCE_SIZE, TAG_SIZE


class TestGCMEncryptDecrypt:

    def setup_method(self):
        self.key = get_random_bytes(32)

    def test_roundtrip_standard_message(self):
        """Encrypt then decrypt returns original plaintext."""
        plaintext = b"Sensitive message"
        assert decrypt_gcm(encrypt_gcm(plaintext, self.key), self.key) == plaintext

    def test_roundtrip_empty_message(self):
        """GCM handles empty plaintext — no padding needed."""
        assert decrypt_gcm(encrypt_gcm(b"", self.key), self.key) == b""

    def test_roundtrip_large_message(self):
        """Multi-block message round-trips correctly."""
        plaintext = b"X" * 10_000
        assert decrypt_gcm(encrypt_gcm(plaintext, self.key), self.key) == plaintext

    def test_unique_ciphertext_per_encryption(self):
        """Same plaintext encrypted twice must produce different output."""
        plaintext = b"Same message"
        assert encrypt_gcm(plaintext, self.key) != encrypt_gcm(plaintext, self.key)

    def test_output_structure(self):
        """Encoded output must contain nonce + tag + ciphertext in correct sizes."""
        plaintext = b"Test"
        raw = base64.b64decode(encrypt_gcm(plaintext, self.key))
        # Minimum length: nonce(12) + tag(16) + at least 1 byte ciphertext
        assert len(raw) >= NONCE_SIZE + TAG_SIZE + len(plaintext)
        # Nonce and tag are exact fixed sizes
        assert len(raw[:NONCE_SIZE]) == NONCE_SIZE
        assert len(raw[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]) == TAG_SIZE


class TestGCMTamperDetection:

    def setup_method(self):
        self.key = get_random_bytes(32)
        self.plaintext = b"Sensitive message"
        self.encrypted = encrypt_gcm(self.plaintext, self.key)

    def test_tamper_ciphertext_detected(self):
        """Flipping a bit in the ciphertext raises ValueError."""
        raw = bytearray(base64.b64decode(self.encrypted))
        raw[NONCE_SIZE + TAG_SIZE] ^= 0xFF   # first byte of ciphertext
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError):
            decrypt_gcm(tampered, self.key)

    def test_tamper_tag_detected(self):
        """Flipping a bit in the tag raises ValueError."""
        raw = bytearray(base64.b64decode(self.encrypted))
        raw[NONCE_SIZE] ^= 0xFF   # first byte of tag
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError):
            decrypt_gcm(tampered, self.key)

    def test_tamper_nonce_detected(self):
        """Changing the nonce causes tag verification to fail."""
        raw = bytearray(base64.b64decode(self.encrypted))
        raw[0] ^= 0xFF   # first byte of nonce
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError):
            decrypt_gcm(tampered, self.key)

    def test_wrong_key_rejected(self):
        """Decrypting with a different key raises ValueError."""
        wrong_key = get_random_bytes(32)
        with pytest.raises(ValueError):
            decrypt_gcm(self.encrypted, wrong_key)

    def test_truncated_ciphertext_rejected(self):
        """Truncated data must not decrypt silently."""
        raw = base64.b64decode(self.encrypted)
        truncated = base64.b64encode(raw[:20]).decode()
        with pytest.raises(Exception):
            decrypt_gcm(truncated, self.key)