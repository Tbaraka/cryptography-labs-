"""
Lab 3.1 — AES-CBC Encryption and Decryption
============================================
Implements AES-256 encryption in CBC mode with PKCS7 padding.

Key design decisions:
- 256-bit key for maximum AES security (vs 128-bit minimum)
- Random IV generated fresh per encryption — NEVER reused
- IV prepended to ciphertext and base64-encoded for safe storage/transmission
- PKCS7 padding validated fully on unpad to detect corruption or tampering
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# ── Constants ────────────────────────────────────────────────────────────────

BLOCK_SIZE = 16  # AES block size is always 16 bytes (128 bits), regardless of key size


# ── Padding ───────────────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes) -> bytes:
    """
    Apply PKCS7 padding to make data length a multiple of BLOCK_SIZE.

    PKCS7 rule: append N bytes each with value N, where N is the number
    of bytes needed to reach the next block boundary.
    If already aligned, append a full block of padding (N = BLOCK_SIZE).
    This ensures unpadding is always unambiguous.

    Args:
        data: Raw plaintext bytes to pad.

    Returns:
        Padded bytes whose length is a multiple of BLOCK_SIZE.
    """
    # Calculate how many bytes are needed to reach the next 16-byte boundary
    # Example: 13 bytes → pad_len = 16 - (13 % 16) = 3
    # Example: 16 bytes → pad_len = 16 - (16 % 16) = 16 (full extra block)
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)

    # Append pad_len bytes, each with the value pad_len
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove and VALIDATE PKCS7 padding.

    This is stricter than the reference code in the lab spec.
    The reference code silently accepts invalid padding, which is a
    security weakness — corrupted or tampered data would be silently
    accepted instead of raising an error.

    Args:
        data: Padded plaintext bytes (output of AES decryption).

    Returns:
        Unpadded bytes.

    Raises:
        ValueError: If data is empty, padding length is invalid, or
                    padding bytes are inconsistent.
    """
    if not data:
        raise ValueError("Cannot unpad empty data.")

    # The last byte tells us how many padding bytes were added
    pad_len = data[-1]

    # Padding must be between 1 and BLOCK_SIZE (inclusive)
    # 0 is invalid, and anything > 16 is impossible in PKCS7
    if pad_len == 0 or pad_len > BLOCK_SIZE:
        raise ValueError(
            f"Invalid padding length: {pad_len}. "
            f"Must be between 1 and {BLOCK_SIZE}."
        )

    # Extract what should be the padding bytes
    padding_bytes = data[-pad_len:]

    # Every padding byte must equal pad_len — if not, data is malformed
    expected_padding = bytes([pad_len]) * pad_len
    if padding_bytes != expected_padding:
        raise ValueError(
            "Invalid PKCS7 padding — data may be corrupted or tampered with."
        )

    # Remove exactly pad_len bytes from the end
    return data[:-pad_len]


# ── Encryption ────────────────────────────────────────────────────────────────

def encrypt_cbc(plaintext: bytes, key: bytes) -> str:
    """
    Encrypt plaintext using AES-256-CBC.

    Steps:
    1. Generate a fresh random IV (16 bytes)
    2. Pad the plaintext to a multiple of 16 bytes
    3. Encrypt using AES-CBC
    4. Prepend IV to ciphertext (IV is not secret, but needed for decryption)
    5. Base64-encode the result for safe storage/transmission

    Args:
        plaintext: The message to encrypt, as bytes.
        key:       32-byte (256-bit) AES key.

    Returns:
        Base64-encoded string: IV (16 bytes) + ciphertext.
    """
    # Fresh random IV for every encryption — NEVER reuse with the same key
    iv = get_random_bytes(BLOCK_SIZE)

    # Pad plaintext before encryption
    padded = pkcs7_pad(plaintext)

    # Create cipher object — a new cipher instance is needed for each operation
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded)

    # Prepend IV so the receiver can use it during decryption
    # Format: [IV (16 bytes)] + [Ciphertext (N bytes)]
    raw = iv + ciphertext

    # Base64-encode so the result is safe to store in a database or send as text
    return base64.b64encode(raw).decode("utf-8")


# ── Decryption ────────────────────────────────────────────────────────────────

def decrypt_cbc(encoded: str, key: bytes) -> bytes:
    """
    Decrypt a base64-encoded AES-256-CBC ciphertext.

    Steps:
    1. Base64-decode to get raw bytes
    2. Split off the first 16 bytes as the IV
    3. Decrypt the remaining bytes using AES-CBC
    4. Validate and remove PKCS7 padding

    Args:
        encoded: Base64-encoded string from encrypt_cbc().
        key:     The same 32-byte key used during encryption.

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError: If padding validation fails (data may be corrupted).
    """
    # Reverse the base64 encoding
    raw = base64.b64decode(encoded)

    # First 16 bytes are the IV — stored there by encrypt_cbc
    iv = raw[:BLOCK_SIZE]
    ciphertext = raw[BLOCK_SIZE:]

    # Create a new cipher instance for decryption — same key, same IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt — this gives us padded plaintext
    padded_plaintext = cipher.decrypt(ciphertext)

    # Remove and validate padding to recover original plaintext
    return pkcs7_unpad(padded_plaintext)


# ── Demo ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  Lab 3.1 — AES-256-CBC Encryption Demo")
    print("=" * 55)

    # Generate a 256-bit (32-byte) AES key — use get_random_bytes, NOT os.urandom
    # in this context for consistency with PyCryptodome's secure random source
    key = get_random_bytes(32)
    print(f"\n[KEY]  {key.hex()}  ({len(key)} bytes / {len(key)*8} bits)")

    # ── Test 1: Standard message ──
    plaintext = b"Hello, AES CBC!"
    print(f"\n[PLAINTEXT]  '{plaintext.decode()}' ({len(plaintext)} bytes)")

    encrypted = encrypt_cbc(plaintext, key)
    print(f"[ENCRYPTED]  {encrypted}")

    decrypted = decrypt_cbc(encrypted, key)
    print(f"[DECRYPTED]  '{decrypted.decode()}'")
    print(f"[MATCH]      {plaintext == decrypted}")

    # ── Test 2: Message that is exactly one block (16 bytes) ──
    # This tests that a full extra padding block is added and removed correctly
    plaintext_exact = b"Exactly 16 bytes"
    print(f"\n[PLAINTEXT]  '{plaintext_exact.decode()}' ({len(plaintext_exact)} bytes — exact block)")

    encrypted2 = encrypt_cbc(plaintext_exact, key)
    decrypted2 = decrypt_cbc(encrypted2, key)
    print(f"[DECRYPTED]  '{decrypted2.decode()}'")
    print(f"[MATCH]      {plaintext_exact == decrypted2}")

    # ── Test 3: Encrypting the same message twice produces different ciphertext ──
    # This demonstrates that a fresh IV is used each time
    enc_a = encrypt_cbc(plaintext, key)
    enc_b = encrypt_cbc(plaintext, key)
    print(f"\n[SAME MSG, ENC 1]  {enc_a}")
    print(f"[SAME MSG, ENC 2]  {enc_b}")
    print(f"[DIFFERENT OUTPUT] {enc_a != enc_b}  ← proves IV is random each time")

    print("\n" + "=" * 55)


if __name__ == "__main__":
    main()