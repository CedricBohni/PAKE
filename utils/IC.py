from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
from hashlib import sha256
import os

def encrypt(key: int, shares: list[tuple[int, int]], P: int) -> str:
    """
    Encrypts the given shares and password using AES-GCM with a key derived from the provided key.

    Args:
        key (int): The key used for encryption.
        shares (list[tuple[int, int]]): The shares to encrypt.
        P (int): The stored password to encrypt.

    Returns:
        str: A JSON string containing the encrypted data (nonce and ciphertext).
    """
    json_safe_shares = [list(pair) for pair in shares]

    data_to_encrypt = json.dumps({
        "shares": json_safe_shares,
        "P": P
    }).encode()

    key_bytes = sha256(str(key).encode()).digest()

    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, data_to_encrypt, None)

    encrypted_blob = {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }

    return json.dumps(encrypted_blob)

def decrypt(key: int, cipher: dict[str, str]) -> tuple[list[tuple[int, int]], str]:
    """
    Decrypts the given ciphertext using AES-GCM with a key derived from the provided key.

    Args:
        key (int): The key used for decryption.
        cipher (dict[str, str]): A dictionary containing the nonce and ciphertext.

    Returns:
        tuple[list[tuple[int, int]], str]: The decrypted shares and password.
    """
    key_bytes = sha256(str(key).encode()).digest()

    nonce = bytes.fromhex(cipher["nonce"])
    ciphertext = bytes.fromhex(cipher["ciphertext"])

    aesgcm = AESGCM(key_bytes)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

    data = json.loads(decrypted_data.decode())

    shares = [tuple(pair) for pair in data["shares"]]
    P = data["pw"]

    return shares, P