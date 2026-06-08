"""
Lab 3.3 — File Encryption and Decryption using AES-GCM
=======================================================
Encrypts and decrypts files using AES-256-GCM with chunked
streaming to avoid loading entire files into memory.

File format (encrypted):
    [ nonce(12) | aad_len(2) | aad(n) | ciphertext(n) | tag(16) ]

Design decisions:
- 64KB chunk size balances memory use and I/O efficiency
- AAD (original filename) is stored inside the encrypted file so
  decryption does not depend on knowing the original filename
- Tag is written at the end after all data is encrypted
- Decryption writes to a temp file first; tag is verified before
  renaming to final output — ensures no unverified plaintext on disk
"""

import os
import tempfile
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ── Constants ─────────────────────────────────────────────────────────────────

NONCE_SIZE   = 12          # 96-bit nonce — GCM recommendation
TAG_SIZE     = 16          # 128-bit authentication tag
AAD_LEN_SIZE = 2           # 2 bytes to store the length of the AAD field
CHUNK_SIZE   = 64 * 1024   # 64KB chunks — memory-efficient streaming


# ── File Encryption ───────────────────────────────────────────────────────────

def encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """
    Encrypt a file using AES-256-GCM with chunked streaming.

    The original filename is used as AAD and stored inside the
    encrypted file so the receiver does not need to know it separately.

    Output file format:
        [ nonce(12) | aad_len(2) | aad(n) | ciphertext(n) | tag(16) ]

    Args:
        input_path  : Path to the plaintext file to encrypt.
        output_path : Path where the encrypted file will be written.
        key         : 32-byte (256-bit) AES key.

    Raises:
        FileNotFoundError : If input_path does not exist.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    # Use original filename as AAD — authenticates the file's identity
    aad = os.path.basename(input_path).encode("utf-8")

    # Fresh nonce for every encryption
    nonce = get_random_bytes(NONCE_SIZE)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)

    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        # Write header: nonce + AAD length (2 bytes) + AAD bytes
        f_out.write(nonce)
        f_out.write(len(aad).to_bytes(AAD_LEN_SIZE, byteorder="big"))
        f_out.write(aad)

        # Encrypt and write in chunks
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            f_out.write(cipher.encrypt(chunk))

        # Append authentication tag at the end
        tag = cipher.digest()
        f_out.write(tag)

    print(f"[ENCRYPTED] {input_path} → {output_path}")
    print(f"            AAD:   {aad}")
    print(f"            Nonce: {nonce.hex()}")
    print(f"            Tag:   {tag.hex()}")


# ── File Decryption ───────────────────────────────────────────────────────────

def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """
    Decrypt and verify a file encrypted with encrypt_file().

    Reads AAD directly from the encrypted file header — no need for
    the caller to know the original filename.

    Uses a temp file to avoid leaving unverified plaintext on disk.
    Only renames to output_path if tag verification passes.

    Args:
        input_path  : Path to the encrypted file.
        output_path : Path where the decrypted file will be written.
        key         : The same 32-byte key used during encryption.

    Raises:
        ValueError        : If authentication tag verification fails.
        FileNotFoundError : If input_path does not exist.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")

    with open(input_path, "rb") as f_in:
        # ── Read header ──
        nonce   = f_in.read(NONCE_SIZE)
        aad_len = int.from_bytes(f_in.read(AAD_LEN_SIZE), byteorder="big")
        aad     = f_in.read(aad_len)

        # ── Calculate ciphertext size ──
        header_size     = NONCE_SIZE + AAD_LEN_SIZE + aad_len
        ciphertext_size = os.path.getsize(input_path) - header_size - TAG_SIZE

        # ── Read tag from end of file ──
        f_in.seek(-TAG_SIZE, 2)
        tag = f_in.read(TAG_SIZE)

        # ── Seek back to start of ciphertext ──
        f_in.seek(header_size)

        # ── Set up cipher with same AAD ──
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)

        # ── Decrypt to temp file first ──
        tmp_fd, tmp_path = tempfile.mkstemp()

        try:
            with os.fdopen(tmp_fd, "wb") as f_tmp:
                bytes_remaining = ciphertext_size
                while bytes_remaining > 0:
                    chunk = f_in.read(min(CHUNK_SIZE, bytes_remaining))
                    if not chunk:
                        break
                    f_tmp.write(cipher.decrypt(chunk))
                    bytes_remaining -= len(chunk)

            # Verify tag AFTER full decryption
            cipher.verify(tag)

            # Tag verified — safe to rename temp file to final output
            os.replace(tmp_path, output_path)
            print(f"[DECRYPTED] {input_path} → {output_path}")
            print(f"            AAD verified: {aad}")
            print(f"            Tag verified successfully")

        except ValueError:
            os.remove(tmp_path)
            raise ValueError(
                "Authentication failed — file may be corrupted or tampered with. "
                "Decrypted output was NOT written."
            )


# ── Demo ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  Lab 3.3 — AES-GCM File Encryption Demo")
    print("=" * 55)

    key = get_random_bytes(32)
    print(f"\n[KEY]  {key.hex()}")

    sample_path    = "sample_files/test_document.txt"
    encrypted_path = "sample_files/test_document.txt.enc"
    decrypted_path = "sample_files/test_document_decrypted.txt"

    os.makedirs("sample_files", exist_ok=True)
    with open(sample_path, "w") as f:
        f.write("This is a secret document.\n")
        f.write("It contains sensitive information.\n")
        f.write("AES-GCM will protect its confidentiality and integrity.\n")

    print(f"\n[ORIGINAL FILE CONTENTS]")
    with open(sample_path) as f:
        print(f.read())

    encrypt_file(sample_path, encrypted_path, key)

    print()
    decrypt_file(encrypted_path, decrypted_path, key)

    print(f"\n[DECRYPTED FILE CONTENTS]")
    with open(decrypted_path) as f:
        print(f.read())

    with open(sample_path, "rb") as f1, open(decrypted_path, "rb") as f2:
        print(f"[FILES MATCH]  {f1.read() == f2.read()}")

    # ── Tamper test ──
    print(f"\n--- Tamper Test ---")
    with open(encrypted_path, "r+b") as f:
        f.seek(30)
        f.write(b"\xFF")

    try:
        decrypt_file(encrypted_path, "sample_files/should_not_exist.txt", key)
    except ValueError as e:
        print(f"[RESULT]  {e}")

    print("\n" + "=" * 55)


if __name__ == "__main__":
    main()