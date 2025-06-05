from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
from hashlib import sha256
import os

def encrypt(key: int, data) -> str:
    """
        Encrypts the given data using AES-GCM with a key derived from the provided integer.

        Args:
            key (int): The integer key used for encryption.
            data (str): The plaintext data to be encrypted.

        Returns:
            str: A JSON string containing the encrypted data and the nonce used for encryption.
    """

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
    """
        Decrypts the given ciphertext using AES-GCM with a key derived from the provided integer.

        Args:
            key (int): The integer key used for decryption.
            cipher (dict[str, str]): A dictionary containing the nonce and ciphertext in hexadecimal format.

        Returns:
            dict: The decrypted data as a dictionary.
    """

    key_bytes = sha256(str(key).encode()).digest()
    nonce = bytes.fromhex(cipher.get("nonce"))
    ciphertext = bytes.fromhex(cipher.get("ciphertext"))

    aesgcm = AESGCM(key_bytes)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

    data = json.loads(decrypted_data.decode())

    return data