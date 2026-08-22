import os
import secrets
import time

from fibcrypt.crypto_utils import decrypt, encrypt

if __name__ == "__main__":
    msg = "Test message"
    password = "example-password"
    salt = "example-context"
    pepper = os.environ.get("FIBCRYPT_PEPPER") or secrets.token_urlsafe(32)

    print("Encrypt process started...")
    t0 = time.time()
    cipher = encrypt(msg, password, salt, pepper)
    print("Encrypt process completed...")

    print("Decrypt process started...")
    clear = decrypt(cipher, password, salt, pepper)
    print("Decrypt process completed...")
    t1 = time.time()

    print(f"Total time: {t1 - t0:.4f} s")
