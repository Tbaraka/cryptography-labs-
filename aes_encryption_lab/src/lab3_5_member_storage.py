"""
Lab 3.5 — Secure Member Data Storage
======================================
Encrypts and decrypts member records using:
- PBKDF2-SHA256 for password-based key derivation
- AES-256-GCM for authenticated encryption
- JSON for record serialization
- Environment variables for passphrase management

Design decisions:
- Passphrase loaded from environment variable MEMBER_PASSPHRASE
  Never hardcoded — missing variable raises EnvironmentError immediately
- Fresh salt + nonce per encryption — identical records produce
  different ciphertext every time
- AES-GCM tag ensures tampered records are rejected, not silently decoded
- JSON serialization handles all standard Python dict value types

Storage format: base64( salt(16) + nonce(12) + tag(16) + ciphertext(n) )
"""

import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC
from dotenv import load_dotenv

# Load .env file into environment variables
load_dotenv()

# ── Constants ─────────────────────────────────────────────────────────────────

SALT_SIZE      = 16       # 128-bit salt — unique per record encryption
NONCE_SIZE     = 12       # 96-bit GCM nonce
TAG_SIZE       = 16       # 128-bit GCM authentication tag
KEY_SIZE       = 32       # AES-256 key length
KDF_ITERATIONS = 200_000  # PBKDF2 iteration count


# ── Passphrase Loading ────────────────────────────────────────────────────────

def _get_passphrase() -> bytes:
    """
    Load the encryption passphrase from the environment variable
    MEMBER_PASSPHRASE.

    Using an environment variable instead of a hardcoded string means
    the passphrase is never stored in source code or version control.

    Returns:
        Passphrase as bytes.

    Raises:
        EnvironmentError : If MEMBER_PASSPHRASE is not set.
    """
    passphrase = os.environ.get("MEMBER_PASSPHRASE")

    if not passphrase:
        raise EnvironmentError(
            "MEMBER_PASSPHRASE environment variable is not set. "
            "Add it to your .env file or export it in your shell."
        )

    return passphrase.encode("utf-8")


# ── Key Derivation ────────────────────────────────────────────────────────────

def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a passphrase and salt using PBKDF2-SHA256.

    Internal function — callers use encrypt/decrypt directly.

    Args:
        passphrase : The raw passphrase bytes.
        salt       : Random 16-byte salt (unique per encryption).

    Returns:
        32-byte AES-256 key.
    """
    return PBKDF2(
        passphrase,
        salt,
        dkLen=KEY_SIZE,
        count=KDF_ITERATIONS,
        prf=lambda p, s: HMAC.new(p, s, SHA256).digest()
    )


# ── Encryption ────────────────────────────────────────────────────────────────

def encrypt_member_record(record: dict) -> str:
    """
    Encrypt a member record dictionary using AES-256-GCM.

    The record is serialized to JSON, then encrypted. A fresh salt
    and nonce are generated for every call — identical records produce
    different ciphertext each time.

    Args:
        record : Dictionary containing member data.
                 Example: {"name": "Alice", "id": "M001", "balance": 1500.00}

    Returns:
        Base64-encoded string: salt(16) + nonce(12) + tag(16) + ciphertext(n)

    Raises:
        EnvironmentError : If MEMBER_PASSPHRASE is not set.
        TypeError        : If record contains non-JSON-serializable values.
    """
    # Load passphrase from environment — raises EnvironmentError if missing
    passphrase = _get_passphrase()

    # Serialize record to JSON bytes
    # sort_keys ensures consistent ordering for readability
    plaintext = json.dumps(record, sort_keys=True).encode("utf-8")

    # Fresh salt and nonce for every encryption
    salt  = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)

    # Derive AES key from passphrase + salt
    key = _derive_key(passphrase, salt)

    # Encrypt and authenticate
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Pack all components needed for decryption
    raw = salt + nonce + tag + ciphertext

    return base64.b64encode(raw).decode("utf-8")


# ── Decryption ────────────────────────────────────────────────────────────────

def decrypt_member_record(encoded: str) -> dict:
    """
    Decrypt and verify an encrypted member record.

    Re-derives the AES key from the stored salt and the environment
    passphrase. If the passphrase is wrong or the record has been
    tampered with, ValueError is raised before any data is returned.

    Args:
        encoded : Base64-encoded string from encrypt_member_record().

    Returns:
        Original member record as a dictionary.

    Raises:
        EnvironmentError : If MEMBER_PASSPHRASE is not set.
        ValueError       : If authentication tag verification fails
                           (wrong passphrase or tampered data).
        json.JSONDecodeError : If decrypted data is not valid JSON
                               (indicates serious data corruption).
    """
    passphrase = _get_passphrase()

    raw = base64.b64decode(encoded)

    # Extract components using known fixed sizes
    salt       = raw[:SALT_SIZE]
    nonce      = raw[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    tag        = raw[SALT_SIZE + NONCE_SIZE : SALT_SIZE + NONCE_SIZE + TAG_SIZE]
    ciphertext = raw[SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

    # Re-derive key — wrong passphrase produces wrong key → tag fails
    key = _derive_key(passphrase, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Decrypt and verify tag — raises ValueError if verification fails
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # Deserialize JSON back to dict
    return json.loads(plaintext.decode("utf-8"))


# ── Demo ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  Lab 3.5 — Secure Member Data Storage")
    print("=" * 55)

    # ── Test 1: Standard member record ──
    member = {
        "name"    : "Alice Wanjiku",
        "id"      : "M001",
        "balance" : 15750.50
    }

    print(f"\n[ORIGINAL RECORD]  {member}")

    encrypted = encrypt_member_record(member)
    print(f"[ENCRYPTED]        {encrypted}")

    decrypted = decrypt_member_record(encrypted)
    print(f"[DECRYPTED RECORD] {decrypted}")
    print(f"[MATCH]            {member == decrypted}")

    # ── Test 2: Same record encrypted twice → different ciphertext ──
    print(f"\n--- Test 2: Unique ciphertext per encryption ---")
    enc_a = encrypt_member_record(member)
    enc_b = encrypt_member_record(member)
    print(f"[ENC 1]  {enc_a[:40]}...")
    print(f"[ENC 2]  {enc_b[:40]}...")
    print(f"[DIFFERENT]  {enc_a != enc_b}  ← fresh salt/nonce each time")

    # ── Test 3: Tamper detection ──
    print(f"\n--- Test 3: Tamper Detection ---")
    raw     = bytearray(base64.b64decode(encrypted))
    raw[40] ^= 0xFF
    tampered = base64.b64encode(bytes(raw)).decode()

    try:
        decrypt_member_record(tampered)
        print("[RESULT]  DANGEROUS: Tampering not detected!")
    except ValueError:
        print("[RESULT]  Tampering detected — ValueError raised correctly")

    # ── Test 4: Wrong passphrase ──
    print(f"\n--- Test 4: Wrong Passphrase ---")
    original_passphrase = os.environ.get("MEMBER_PASSPHRASE")
    os.environ["MEMBER_PASSPHRASE"] = "wrong_passphrase"

    try:
        decrypt_member_record(encrypted)
        print("[RESULT]  DANGEROUS: Wrong passphrase accepted!")
    except ValueError:
        print("[RESULT]  Wrong passphrase rejected — ValueError raised correctly")
    finally:
        # Restore original passphrase
        os.environ["MEMBER_PASSPHRASE"] = original_passphrase

    print("\n" + "=" * 55)


if __name__ == "__main__":
    main()