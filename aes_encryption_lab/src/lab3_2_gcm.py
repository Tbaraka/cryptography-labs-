"""
Lab 3.2 — AES-GCM Authenticated Encryption
===========================================
Implements AES-256 in GCM mode, providing both confidentiality
and integrity (authenticated encryption).

Key differences from Lab 3.1 (CBC):
- No padding required — GCM handles arbitrary length plaintext
- Produces an authentication tag alongside ciphertext
- Any modification to ciphertext or tag causes decryption to fail
- Nonce is 12 bytes (vs 16-byte IV in CBC)

Storage format: base64( nonce[12] + tag[16] + ciphertext[n] )
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# ── Constants ─────────────────────────────────────────────────────────────────

NONCE_SIZE = 12   # 96-bit nonce — GCM standard recommendation
TAG_SIZE   = 16   # 128-bit authentication tag — GCM default, do not reduce


# ── Encryption ────────────────────────────────────────────────────────────────

def encrypt_gcm(plaintext: bytes, key: bytes) -> str:
    """
    Encrypt plaintext using AES-256-GCM.

    GCM produces both ciphertext and an authentication tag.
    The tag allows the receiver to verify nothing was tampered with.

    Storage format (all base64-encoded together):
        [ nonce (12 bytes) | tag (16 bytes) | ciphertext (n bytes) ]

    Args:
        plaintext : Message to encrypt, as bytes.
        key       : 32-byte (256-bit) AES key.

    Returns:
        Base64-encoded string containing nonce + tag + ciphertext.
    """
    # Fresh nonce for every encryption — NEVER reuse with the same key
    # In GCM, nonce reuse is catastrophic (attacker recovers keystream)
    nonce = get_random_bytes(NONCE_SIZE)

    # Create GCM cipher — no padding needed, GCM handles any plaintext length
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # encrypt_and_digest returns ciphertext AND the authentication tag
    # The tag is a 16-byte fingerprint of the ciphertext + key + nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Pack: nonce + tag + ciphertext
    # Both nonce and tag are fixed size, so we can reliably split them on decrypt
    raw = nonce + tag + ciphertext

    return base64.b64encode(raw).decode("utf-8")


# ── Decryption ────────────────────────────────────────────────────────────────

def decrypt_gcm(encoded: str, key: bytes) -> bytes:
    """
    Decrypt and verify an AES-256-GCM encrypted message.

    Verification happens automatically inside decrypt_and_verify.
    If the tag does not match, a ValueError is raised immediately —
    the plaintext is never returned to the caller if verification fails.

    Args:
        encoded : Base64-encoded string from encrypt_gcm().
        key     : The same 32-byte key used during encryption.

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError : If authentication tag verification fails.
                     This means the ciphertext, tag, or nonce was modified.
    """
    raw = base64.b64decode(encoded)

    # Split the three components using their known fixed sizes
    nonce      = raw[:NONCE_SIZE]               # bytes 0–11
    tag        = raw[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]   # bytes 12–27
    ciphertext = raw[NONCE_SIZE + TAG_SIZE:]    # bytes 28 onwards

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # decrypt_and_verify decrypts AND checks the tag in one operation
    # If tag is invalid, raises ValueError before returning any plaintext
    # This prevents partial decryption of tampered data
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext


# ── Demo ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  Lab 3.2 — AES-256-GCM Authenticated Encryption")
    print("=" * 55)

    key = get_random_bytes(32)
    print(f"\n[KEY]  {key.hex()}  ({len(key) * 8} bits)")

    # ── Test 1: Normal encrypt / decrypt ──
    plaintext = b"Sensitive message"
    print(f"\n--- Test 1: Normal Encryption ---")
    print(f"[PLAINTEXT]   '{plaintext.decode()}'")

    encrypted = encrypt_gcm(plaintext, key)
    print(f"[ENCRYPTED]   {encrypted}")

    decrypted = decrypt_gcm(encrypted, key)
    print(f"[DECRYPTED]   '{decrypted.decode()}'")
    print(f"[MATCH]       {plaintext == decrypted}")

    # ── Test 2: Tamper with the ciphertext ──
    # Decode, flip one byte in the ciphertext region, re-encode
    print(f"\n--- Test 2: Tamper with Ciphertext ---")
    raw = bytearray(base64.b64decode(encrypted))

    # Ciphertext starts at byte 28 (after 12-byte nonce + 16-byte tag)
    raw[28] ^= 0xFF   # XOR with 0xFF flips all bits in that byte
    tampered = base64.b64encode(bytes(raw)).decode("utf-8")
    print(f"[TAMPERED]    {tampered}")

    try:
        decrypt_gcm(tampered, key)
        print("[RESULT]      DANGEROUS: Tampering was NOT detected!")
    except ValueError:
        print("[RESULT]      Tampering detected — ValueError raised correctly")

    # ── Test 3: Tamper with the tag itself ──
    print(f"\n--- Test 3: Tamper with the Tag ---")
    raw2 = bytearray(base64.b64decode(encrypted))

    # Tag occupies bytes 12–27
    raw2[12] ^= 0xFF   # Flip a bit in the tag
    tampered2 = base64.b64encode(bytes(raw2)).decode("utf-8")

    try:
        decrypt_gcm(tampered2, key)
        print("[RESULT]      DANGEROUS: Tag tampering was NOT detected!")
    except ValueError:
        print("[RESULT]      Tag tampering detected — ValueError raised correctly")

    # ── Test 4: Same message encrypted twice gives different output ──
    print(f"\n--- Test 4: Nonce Uniqueness ---")
    enc_a = encrypt_gcm(plaintext, key)
    enc_b = encrypt_gcm(plaintext, key)
    print(f"[ENC 1]  {enc_a}")
    print(f"[ENC 2]  {enc_b}")
    print(f"[DIFFERENT OUTPUT]  {enc_a != enc_b}  ← fresh nonce each time")

    print("\n" + "=" * 55)


if __name__ == "__main__":
    main()