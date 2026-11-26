"""Ideal-cipher stand-in: AES-GCM keyed by SHA-256 of an integer group element."""

import json
import os
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _key_bytes(key: int) -> bytes:
    return sha256(str(key).encode()).digest()


def encrypt(key: int, data: str) -> str:
    """
    Encrypts the given data using AES-GCM with a key derived from the provided integer.

    Args:
        key (int): The integer key used for encryption.
        data (str): The plaintext data to be encrypted.

    Returns:
        str: A JSON string containing the encrypted data and the nonce used for encryption.
    """
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key_bytes(key)).encrypt(nonce, data.encode(), None)
    return json.dumps({"nonce": nonce.hex(), "ciphertext": ciphertext.hex()})


def decrypt(key: int, cipher: dict[str, str]):
    """
    Decrypts the given ciphertext using AES-GCM with a key derived from the provided integer.

    Args:
        key (int): The integer key used for decryption.
        cipher (dict[str, str]): A dictionary containing the nonce and ciphertext in hexadecimal format.

    Returns:
        The decrypted JSON data.

    Raises:
        cryptography.exceptions.InvalidTag: if the key is wrong or the ciphertext was modified.
    """
    nonce = bytes.fromhex(cipher["nonce"])
    ciphertext = bytes.fromhex(cipher["ciphertext"])
    decrypted_data = AESGCM(_key_bytes(key)).decrypt(nonce, ciphertext, None)
    return json.loads(decrypted_data.decode())
