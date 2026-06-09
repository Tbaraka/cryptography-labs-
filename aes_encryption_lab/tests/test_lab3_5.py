"""
tests/test_lab3_5.py
Unit tests for Lab 3.5 — Secure Member Data Storage
"""

import os
import base64
import pytest
from unittest.mock import patch
from src.lab3_5_member_storage import (
    encrypt_member_record,
    decrypt_member_record,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def set_passphrase():
    """
    Set a test passphrase for every test automatically.
    autouse=True means this runs for every test without needing
    to request it explicitly.
    """
    with patch.dict(os.environ, {"MEMBER_PASSPHRASE": "test_passphrase_for_lab"}):
        yield


@pytest.fixture
def sample_member():
    return {
        "name"    : "Alice Wanjiku",
        "id"      : "M001",
        "balance" : 15750.50
    }


# ── Roundtrip Tests ───────────────────────────────────────────────────────────

class TestMemberRecordRoundtrip:

    def test_roundtrip_standard_record(self, sample_member):
        """Encrypt then decrypt returns the original record."""
        encrypted = encrypt_member_record(sample_member)
        decrypted = decrypt_member_record(encrypted)
        assert decrypted == sample_member

    def test_roundtrip_all_field_types(self):
        """All common field types survive JSON serialization."""
        record = {
            "name"    : "Bob Otieno",
            "id"      : "M002",
            "balance" : 0.99,          # float
            "active"  : True,          # boolean
            "score"   : 42,            # integer
        }
        assert decrypt_member_record(encrypt_member_record(record)) == record

    def test_roundtrip_unicode_name(self):
        """Unicode characters in member names are handled correctly."""
        record = {"name": "Müller François", "id": "M003", "balance": 100.0}
        assert decrypt_member_record(encrypt_member_record(record)) == record

    def test_roundtrip_zero_balance(self):
        """Zero balance is preserved exactly."""
        record = {"name": "Carol", "id": "M004", "balance": 0.0}
        assert decrypt_member_record(encrypt_member_record(record)) == record

    def test_roundtrip_large_balance(self):
        """Large float balance survives round-trip without precision loss."""
        record = {"name": "Dave", "id": "M005", "balance": 999999.99}
        assert decrypt_member_record(encrypt_member_record(record)) == record

    def test_unique_ciphertext_per_encryption(self, sample_member):
        """Same record encrypted twice produces different ciphertext."""
        enc1 = encrypt_member_record(sample_member)
        enc2 = encrypt_member_record(sample_member)
        assert enc1 != enc2

    def test_output_is_valid_base64(self, sample_member):
        """Output must be valid base64-encoded string."""
        encrypted = encrypt_member_record(sample_member)
        # Should not raise
        raw = base64.b64decode(encrypted)
        assert len(raw) >= SALT_SIZE + NONCE_SIZE + TAG_SIZE


# ── Tamper Detection Tests ────────────────────────────────────────────────────

class TestTamperDetection:

    def test_tamper_ciphertext_detected(self, sample_member):
        """Flipping a bit in the ciphertext raises ValueError."""
        encrypted = encrypt_member_record(sample_member)
        raw       = bytearray(base64.b64decode(encrypted))
        raw[SALT_SIZE + NONCE_SIZE + TAG_SIZE] ^= 0xFF
        tampered  = base64.b64encode(bytes(raw)).decode()

        with pytest.raises(ValueError):
            decrypt_member_record(tampered)

    def test_tamper_tag_detected(self, sample_member):
        """Flipping a bit in the tag raises ValueError."""
        encrypted = encrypt_member_record(sample_member)
        raw       = bytearray(base64.b64decode(encrypted))
        raw[SALT_SIZE + NONCE_SIZE] ^= 0xFF
        tampered  = base64.b64encode(bytes(raw)).decode()

        with pytest.raises(ValueError):
            decrypt_member_record(tampered)

    def test_tamper_nonce_detected(self, sample_member):
        """Changing the nonce causes tag verification to fail."""
        encrypted = encrypt_member_record(sample_member)
        raw       = bytearray(base64.b64decode(encrypted))
        raw[SALT_SIZE] ^= 0xFF
        tampered  = base64.b64encode(bytes(raw)).decode()

        with pytest.raises(ValueError):
            decrypt_member_record(tampered)


# ── Key Management Tests ──────────────────────────────────────────────────────

class TestKeyManagement:

    def test_wrong_passphrase_rejected(self, sample_member):
        """Decrypting with wrong passphrase raises ValueError."""
        encrypted = encrypt_member_record(sample_member)

        with patch.dict(os.environ, {"MEMBER_PASSPHRASE": "wrong_passphrase"}):
            with pytest.raises(ValueError):
                decrypt_member_record(encrypted)

    def test_missing_passphrase_raises_environment_error(self, sample_member):
        """Missing MEMBER_PASSPHRASE raises EnvironmentError immediately."""
        env = os.environ.copy()
        env.pop("MEMBER_PASSPHRASE", None)

        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(EnvironmentError):
                encrypt_member_record(sample_member)

    def test_different_passphrases_produce_different_ciphertext(self, sample_member):
        """Same record encrypted with different passphrases produces different output."""
        enc1 = encrypt_member_record(sample_member)

        with patch.dict(os.environ, {"MEMBER_PASSPHRASE": "different_passphrase"}):
            enc2 = encrypt_member_record(sample_member)

        assert enc1 != enc2