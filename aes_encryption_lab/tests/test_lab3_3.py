"""
tests/test_lab3_3.py
Unit tests for Lab 3.3 — AES-GCM File Encryption
"""

import os
import pytest
from Crypto.Random import get_random_bytes
from src.lab3_3_file_enc import (
    encrypt_file,
    decrypt_file,
    NONCE_SIZE,
    TAG_SIZE,
    AAD_LEN_SIZE,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_files(tmp_path):
    """Provide temp file paths for each test — auto-cleaned by pytest."""
    return {
        "plain"     : str(tmp_path / "plain.txt"),
        "encrypted" : str(tmp_path / "plain.txt.enc"),
        "decrypted" : str(tmp_path / "plain_dec.txt"),
    }


@pytest.fixture
def key():
    return get_random_bytes(32)


# ── Encryption / Decryption Tests ─────────────────────────────────────────────

class TestFileEncryption:

    def test_roundtrip_small_file(self, tmp_files, key):
        """Small file encrypts and decrypts to original content."""
        content = b"Hello, file encryption!"
        with open(tmp_files["plain"], "wb") as f:
            f.write(content)

        encrypt_file(tmp_files["plain"], tmp_files["encrypted"], key)
        decrypt_file(tmp_files["encrypted"], tmp_files["decrypted"], key)

        with open(tmp_files["decrypted"], "rb") as f:
            assert f.read() == content

    def test_roundtrip_large_file(self, tmp_files, key):
        """Large file (>64KB) is streamed correctly across multiple chunks."""
        content = os.urandom(200 * 1024)   # 200KB — spans multiple chunks
        with open(tmp_files["plain"], "wb") as f:
            f.write(content)

        encrypt_file(tmp_files["plain"], tmp_files["encrypted"], key)
        decrypt_file(tmp_files["encrypted"], tmp_files["decrypted"], key)

        with open(tmp_files["decrypted"], "rb") as f:
            assert f.read() == content

    def test_roundtrip_empty_file(self, tmp_files, key):
        """Empty file encrypts and decrypts correctly."""
        with open(tmp_files["plain"], "wb") as f:
            f.write(b"")

        encrypt_file(tmp_files["plain"], tmp_files["encrypted"], key)
        decrypt_file(tmp_files["encrypted"], tmp_files["decrypted"], key)

        with open(tmp_files["decrypted"], "rb") as f:
            assert f.read() == b""

    def test_encrypted_file_has_correct_overhead(self, tmp_files, key):
        """
        Encrypted file size = original + nonce(12) + aad_len(2) + aad(n) + tag(16).
        AAD is the original filename stored in the header for self-contained decryption.
        """
        content = b"Exactly this content"
        with open(tmp_files["plain"], "wb") as f:
            f.write(content)

        encrypt_file(tmp_files["plain"], tmp_files["encrypted"], key)

        aad = os.path.basename(tmp_files["plain"]).encode("utf-8")

        original_size  = os.path.getsize(tmp_files["plain"])
        encrypted_size = os.path.getsize(tmp_files["encrypted"])

        expected_size = (
            original_size
            + NONCE_SIZE      # 12 bytes
            + AAD_LEN_SIZE    # 2 bytes
            + len(aad)        # variable — depends on filename length
            + TAG_SIZE        # 16 bytes
        )
        assert encrypted_size == expected_size


# ── Tamper Detection Tests ────────────────────────────────────────────────────

class TestFileTamperDetection:

    def test_tamper_ciphertext_detected(self, tmp_files, key):
        """Modifying ciphertext raises ValueError — no output file created."""
        content = b"Sensitive file contents"
        with open(tmp_files["plain"], "wb") as f:
            f.write(content)

        encrypt_file(tmp_files["plain"], tmp_files["encrypted"], key)

        # Flip a byte well into the ciphertext region (past the header)
        with open(tmp_files["encrypted"], "r+b") as f:
            f.seek(40)
            f.write(b"\xFF")

        with pytest.raises(ValueError):
            decrypt_file(tmp_files["encrypted"], tmp_files["decrypted"], key)

        # Verify no output file was written
        assert not os.path.exists(tmp_files["decrypted"])

    def test_wrong_key_rejected(self, tmp_files, key):
        """Decrypting with a different key raises ValueError."""
        with open(tmp_files["plain"], "wb") as f:
            f.write(b"Secret content")

        encrypt_file(tmp_files["plain"], tmp_files["encrypted"], key)

        with pytest.raises(ValueError):
            decrypt_file(
                tmp_files["encrypted"],
                tmp_files["decrypted"],
                get_random_bytes(32)   # wrong key
            )

    def test_missing_input_file_raises(self, tmp_files, key):
        """Encrypting a non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            encrypt_file("nonexistent.txt", tmp_files["encrypted"], key)