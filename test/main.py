import time

from fibcrypt.crypto_utils import decrypt, encrypt

if __name__ == "__main__":
    msg = "Test message 🚀"
    password = "strongPasswd1234"
    salt = "user@example.com"
    pepper = "deployment-secret-with-at-least-32-bytes"

    print("Encrypt process started...")
    t0 = time.time()
    cipher = encrypt(msg, password, salt, pepper)
    print("Encrypt process completed...")

    print("Decrypt process started...")
    clear = decrypt(cipher, password, salt, pepper)
    print("Decrypt process completed...")
    print("Decrypt process completed...")
    t1 = time.time()

    print(f"[⏱️] Grand Total Time: {t1 - t0:.4f} s")
