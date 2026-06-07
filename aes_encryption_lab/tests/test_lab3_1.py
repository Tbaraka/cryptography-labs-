"""
tests/test_lab3_1.py
Unit tests for Lab 3.1 — AES-CBC
"""

import pytest
from Crypto.Random import get_random_bytes
from src.lab3_1_cbc import encrypt_cbc, decrypt_cbc, pkcs7_pad, pkcs7_unpad, BLOCK_SIZE


class TestPKCS7Padding:

    def test_pad_short_message(self):
        """13 bytes needs 3 bytes of padding."""
        data = b"Hello, World!"   # 13 bytes
        padded = pkcs7_pad(data)
        assert len(padded) == 16
        assert padded[-3:] == b"\x03\x03\x03"

    def test_pad_exact_block(self):
        """16 bytes must add a full extra block of padding."""
        data = b"Exactly 16 bytes"   # 16 bytes
        padded = pkcs7_pad(data)
        assert len(padded) == 32
        assert padded[-16:] == bytes([16]) * 16

    def test_pad_empty_string(self):
        """Empty input should produce a full padding block."""
        padded = pkcs7_pad(b"")
        assert len(padded) == 16
        assert padded == bytes([16]) * 16

    def test_unpad_valid_padding(self):
        """Unpadding correctly padded data returns original."""
        data = b"Hello, World!\x03\x03\x03"
        assert pkcs7_unpad(data) == b"Hello, World!"

    def test_unpad_rejects_empty(self):
        """Unpadding empty bytes raises ValueError."""
        with pytest.raises(ValueError, match="empty"):
            pkcs7_unpad(b"")

    def test_unpad_rejects_zero_pad_len(self):
        """A final byte of 0x00 is not valid PKCS7 padding."""
        with pytest.raises(ValueError):
            pkcs7_unpad(b"some data\x00")

    def test_unpad_rejects_oversized_pad_len(self):
        """A padding length > BLOCK_SIZE is impossible and must be rejected."""
        with pytest.raises(ValueError):
            pkcs7_unpad(b"some data\x11")   # 0x11 = 17, which exceeds BLOCK_SIZE

    def test_unpad_rejects_inconsistent_padding(self):
        """Padding bytes that don't all match are invalid."""
        with pytest.raises(ValueError, match="corrupted or tampered"):
            pkcs7_unpad(b"Hello, World!\x03\x03\x02")  # last byte doesn't match


class TestCBCEncryptDecrypt:

    def setup_method(self):
        """Fresh key for every test — never share keys between tests."""
        self.key = get_random_bytes(32)

    def test_roundtrip_standard_message(self):
        """Encrypt then decrypt returns the original plaintext."""
        plaintext = b"Hello, AES CBC!"
        assert decrypt_cbc(encrypt_cbc(plaintext, self.key), self.key) == plaintext

    def test_roundtrip_exact_block_length(self):
        """A 16-byte message is correctly padded and unpadded."""
        plaintext = b"Exactly 16 bytes"
        assert decrypt_cbc(encrypt_cbc(plaintext, self.key), self.key) == plaintext

    def test_roundtrip_empty_string(self):
        """Empty plaintext encrypts and decrypts correctly."""
        plaintext = b""
        assert decrypt_cbc(encrypt_cbc(plaintext, self.key), self.key) == plaintext

    def test_roundtrip_large_message(self):
        """Multi-block message encrypts and decrypts correctly."""
        plaintext = b"A" * 1000
        assert decrypt_cbc(encrypt_cbc(plaintext, self.key), self.key) == plaintext

    def test_different_ciphertext_per_encryption(self):
        """Same plaintext encrypted twice must produce different ciphertext (random IV)."""
        plaintext = b"Same message"
        enc1 = encrypt_cbc(plaintext, self.key)
        enc2 = encrypt_cbc(plaintext, self.key)
        assert enc1 != enc2

    def test_wrong_key_fails(self):
        """Decrypting with a wrong key must fail — either bad padding or garbage output."""
        plaintext = b"Secret message"
        encrypted = encrypt_cbc(plaintext, self.key)
        wrong_key = get_random_bytes(32)
        with pytest.raises((ValueError, Exception)):
            decrypt_cbc(encrypted, wrong_key)