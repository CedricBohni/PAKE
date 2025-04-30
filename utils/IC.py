from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
from hashlib import sha256
import os

def encrypt(key: int, data) -> str:

    key_bytes = sha256(str(key).encode()).digest()

    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)

    encrypted_blob = {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }

    return json.dumps(encrypted_blob)

def decrypt(key: int, cipher: dict[str, str]):

    key_bytes = sha256(str(key).encode()).digest()

    nonce = bytes.fromhex(cipher["nonce"])
    ciphertext = bytes.fromhex(cipher["ciphertext"])

    aesgcm = AESGCM(key_bytes)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

    data = json.loads(decrypted_data.decode())

    return data