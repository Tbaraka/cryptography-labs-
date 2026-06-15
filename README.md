# Cryptography Labs

A collection of small cryptography exercises and lab implementations in Python and C++, covering classical ciphers, RSA key generation primitives, AES encryption modes, password-based key derivation, and a practical brute-force exercise on broken cryptography.

## Contents

| Path | Topic | Language |
|---|---|---|
| `aes_encryption_lab/` | AES-CBC, AES-GCM, file encryption, PBKDF2 key derivation, encrypted record storage | Python |
| `key generation algorithm.py` | RSA-style prime pair generation (p, q) | Python |
| `EulerTotient2.py` | Prime generation + Euler's totient function (naive and optimized) | Python |
|
| `XORencryption_lab.cpp` | Single-byte XOR encrypt/decrypt | C++ |
| `cryptographic failure brute force .py` | Brute-forces a partially-known repeating-key XOR key against Base64 ciphertexts (OWASP/TryHackMe style exercise) | Python |
| `EncryptionKeys.py` | Smoke test confirming PyCryptodome is installed | Python |
| `Key Generation Algorithm .pdf` | Lab report for the RSA key generation exercise | PDF |

## Setup

These labs use [PyCryptodome](https://pycryptodome.readthedocs.io/) and, for the AES member-storage lab, `python-dotenv` and `pytest`.

```bash
python3 -m venv venv
source venv/bin/activate
pip install pycryptodome python-dotenv pytest
```

> Note: there is currently no `requirements.txt`. If you add one, it should pin at least `pycryptodome`, `python-dotenv`, and `pytest`.

## AES Encryption Lab (`aes_encryption_lab/`)

A progressive set of AES labs, each building on the last:

- **Lab 3.1 — `lab3_1_cbc.py`**: AES-256-CBC with PKCS7 padding. Generates a fresh random IV per encryption, prepends it to the ciphertext, and base64-encodes the result.
- **Lab 3.2 — `lab3_2_gcm.py`**: AES-256-GCM authenticated encryption. No padding needed; produces a 16-byte authentication tag so tampering is detected on decryption.
- **Lab 3.3 — `lab3_3_file_enc.py`**: Streams file encryption/decryption in 64KB chunks using AES-GCM, storing the original filename as associated data (AAD) inside the encrypted file.
- **Lab 3.4 — `lab3_4_pbkdf2.py`**: Derives a 256-bit AES key from a passphrase using PBKDF2-SHA256 (200,000 iterations) with a random salt, then encrypts with AES-GCM.
- **Lab 3.5 — `lab3_5_member_storage.py`**: Encrypts/decrypts JSON member records using PBKDF2 + AES-GCM. The passphrase is read from the `MEMBER_PASSPHRASE` environment variable (via a `.env` file, never hardcoded).

### Running the AES lab tests

```bash
cd aes_encryption_lab
pytest
```

For Lab 3.5, set a passphrase before running the module directly (the test suite sets this automatically via a fixture):

```bash
export MEMBER_PASSPHRASE="your-test-passphrase"
python -m src.lab3_5_member_storage
```

## RSA Key Generation Primitives

- `key generation algorithm.py` and `EulerTotient2.py` generate two distinct primes `p` and `q` within a user-specified range — the first step of RSA key generation.
- `EulerTotient2.py` additionally computes Euler's totient function φ(n), both naively (O(n)) and via an optimized prime-factorization approach.
- `Key Generation Algorithm .pdf` is the accompanying write-up for this exercise.

Run either script and follow the prompts:

```bash
python3 EulerTotient2.py
```

## XOR Cipher (`XORencryption_lab.cpp`)

A minimal single-byte XOR cipher. Since XOR is its own inverse, the same function both encrypts and decrypts.

```bash
g++ -o xor_lab XORencryption_lab.cpp
./xor_lab
```

## Cryptographic Failure Brute Force (`cryptographic failure brute force .py`)

Given three Base64-encoded ciphertexts encrypted with a repeating-key XOR cipher where the key is known to start with `"KEY"` and have one unknown trailing character, this script brute-forces that final character by checking which candidate key decrypts all three ciphertexts to valid UTF-8.

```bash
python3 "cryptographic failure brute force .py"
```

## License

No license file is currently included. Add one (e.g. MIT) if you want others to be able to reuse this code.
