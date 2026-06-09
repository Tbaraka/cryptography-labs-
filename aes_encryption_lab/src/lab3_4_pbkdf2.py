"""
Lab 3.4 — Password-Based Key Derivation with PBKDF2
=====================================================
Derives an AES-256 key from a passphrase using PBKDF2-SHA256,
then encrypts using AES-GCM for authenticated encryption.

Why PBKDF2:
- Raw passwords are too short and predictable for direct use as keys
- PBKDF2 stretches the password into a full 256-bit key
- Salt ensures two identical passwords produce different keys
- High iteration count (200,000) makes brute-force attacks slow

Storage format: base64( salt(16) + nonce(12) + tag(16) + ciphertext(n) )
"""

import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# ── Constants ─────────────────────────────────────────────────────────────────

SALT_SIZE       = 16      # 128-bit salt — unique per encryption
NONCE_SIZE      = 12      # 96-bit GCM nonce
TAG_SIZE        = 16      # 128-bit GCM authentication tag
KEY_SIZE        = 32      # 256-bit AES key
KDF_ITERATIONS  = 200_000 # PBKDF2 iteration count — adjust higher for production


# ── Key Derivation ────────────────────────────────────────────────────────────

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a password using PBKDF2-SHA256.

    PBKDF2 is intentionally slow — 200,000 iterations means an attacker
    must perform 200,000 SHA-256 operations per password guess, making
    brute-force attacks computationally expensive.

    Args:
        password : The passphrase as bytes.
        salt     : Random 16-byte salt. Must be unique per encryption.
                   Not secret — stored alongside ciphertext.

    Returns:
        32-byte derived key suitable for AES-256.
    """
    return PBKDF2(
        password,
        salt,
        dkLen=KEY_SIZE,          # derive 32 bytes (256 bits)
        count=KDF_ITERATIONS,    # number of hash iterations
        prf=lambda p, s: SHA256.new(p).update(s) or SHA256.new(p + s).digest()
        # Using HMAC-SHA256 internally — standard PBKDF2 pseudorandom function
    )


# ── Encryption ────────────────────────────────────────────────────────────────

def encrypt_with_password(plaintext: bytes, password: bytes) -> str:
    """
    Encrypt plaintext using a password-derived AES-256-GCM key.

    A fresh salt and nonce are generated for every encryption.
    This means encrypting the same plaintext with the same password
    twice produces completely different output — intentional.

    Storage format (base64-encoded):
        [ salt(16) | nonce(12) | tag(16) | ciphertext(n) ]

    Args:
        plaintext : Data to encrypt, as bytes.
        password  : Human passphrase as bytes.

    Returns:
        Base64-encoded string containing all components needed for decryption.
    """
    # Fresh salt for every encryption — ensures unique key even for same password
    salt  = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)

    # Derive AES key from password + salt
    key = derive_key(password, salt)

    # Encrypt with AES-GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Pack all components needed for decryption into one blob
    raw = salt + nonce + tag + ciphertext

    return base64.b64encode(raw).decode("utf-8")


# ── Decryption ────────────────────────────────────────────────────────────────

def decrypt_with_password(encoded: str, password: bytes) -> bytes:
    """
    Decrypt a password-encrypted message.

    Re-derives the AES key from the stored salt and the provided password.
    If the password is wrong, key derivation produces a different key,
    causing GCM tag verification to fail with ValueError.

    Args:
        encoded  : Base64-encoded string from encrypt_with_password().
        password : The same passphrase used during encryption.

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError : If tag verification fails — wrong password or tampered data.
    """
    raw = base64.b64decode(encoded)

    # Extract components using known fixed sizes
    salt       = raw[:SALT_SIZE]
    nonce      = raw[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    tag        = raw[SALT_SIZE + NONCE_SIZE : SALT_SIZE + NONCE_SIZE + TAG_SIZE]
    ciphertext = raw[SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

    # Re-derive the key using the stored salt and provided password
    # Wrong password → different key → tag verification fails
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Decrypt and verify in one operation
    return cipher.decrypt_and_verify(ciphertext, tag)


# ── Demo ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  Lab 3.4 — PBKDF2 Password-Based Encryption")
    print("=" * 55)

    password  = b"my secret password"
    plaintext = b"Sensitive data protected by a password"

    print(f"\n[PASSWORD]   '{password.decode()}'")
    print(f"[PLAINTEXT]  '{plaintext.decode()}'")
    print(f"[ITERATIONS] {KDF_ITERATIONS:,}")

    # ── Test 1: Normal encrypt / decrypt ──
    print(f"\n--- Test 1: Normal Encryption ---")
    encrypted = encrypt_with_password(plaintext, password)
    print(f"[ENCRYPTED]  {encrypted}")

    decrypted = decrypt_with_password(encrypted, password)
    print(f"[DECRYPTED]  '{decrypted.decode()}'")
    print(f"[MATCH]      {plaintext == decrypted}")

    # ── Test 2: Same password, same plaintext → different ciphertext ──
    print(f"\n--- Test 2: Salt Uniqueness ---")
    enc_a = encrypt_with_password(plaintext, password)
    enc_b = encrypt_with_password(plaintext, password)
    print(f"[ENC 1]  {enc_a}")
    print(f"[ENC 2]  {enc_b}")
    print(f"[DIFFERENT]  {enc_a != enc_b}  ← fresh salt each time")

    # ── Test 3: Wrong password fails ──
    print(f"\n--- Test 3: Wrong Password ---")
    try:
        decrypt_with_password(encrypted, b"wrong password")
        print("[RESULT]  DANGEROUS: Wrong password was accepted!")
    except ValueError:
        print("[RESULT]  Wrong password rejected — ValueError raised correctly")

    print("\n" + "=" * 55)


if __name__ == "__main__":
    main()