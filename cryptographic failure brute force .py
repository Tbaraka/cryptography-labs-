import base64
import string

# Paste the three Base64 ciphertexts from the challenge here
ciphertexts = [
    "BiA8RSIrPhE4JjFULzA1VC9lP145ZS1eJiorQyQyeVA/ZWoRGwh3EQgqN1cuNzxfKCB5QyQqNBEJaw==",
    "GyQqQjwqK1VrNzxCLjF5XSIrMgtrLS1FOzZjHmQsN0UuNzdQJ2stWSZqK1Q4IC0OPyoyVCV4OFModGsC",
    "GAAaYw4RYxEfDRRKHAAYehQGC2gbERZuDQkYdjZldBEPKnlfJDF5QiMkK1RrMTFYOGUuWD8teUQlJCxFIyorWDEgPRE7ICtCJCs3VCdr"
]

# Try all possible letters and digits for the 4th character
for ch in string.ascii_letters + string.digits:

    # Construct the candidate key
    key = f"KEY{ch}".encode()

    valid = True
    results = []

    # Attempt to decrypt all ciphertexts with the current key
    for ct in ciphertexts:
        try:
            # Decode Base64 into raw bytes
            data = base64.b64decode(ct)

            # Repeating-key XOR decryption
            plaintext = bytes(
                b ^ key[i % len(key)]
                for i, b in enumerate(data)
            )

            # Convert decrypted bytes to text
            text = plaintext.decode("utf-8")

            # Store result for later display
            results.append(text)

        except:
            # If decoding fails, this key is probably wrong
            valid = False
            break

    # Print any key that produces valid UTF-8 text
    if valid:
        print(f"\n{'=' * 50}")
        print(f"Possible Key: KEY{ch}")
        print(f"{'=' * 50}")

        for i, text in enumerate(results, start=1):
            print(f"\nNote {i}:")
            print(text)