import random
from sympy import symbols, mod_inverse
import itertools
from collections import Counter, defaultdict
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256
import os

p_hex = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22
514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6
F44C42E9A63A3620FFFFFFFFFFFFFFFF
""".replace("\n", "").replace(" ", "")

PRIME = int(p_hex, 16)
g = 2

def encrypt(key, shares, pw ):
    json_safe_shares = [list(pair) for pair in shares]

    data_to_encrypt = json.dumps({
        "shares": json_safe_shares,
        "pw": pw
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

def decrypt(key, cipher):
    key_bytes = sha256(str(key).encode()).digest()

    nonce = bytes.fromhex(cipher["nonce"])
    ciphertext = bytes.fromhex(cipher["ciphertext"])

    aesgcm = AESGCM(key_bytes)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

    data = json.loads(decrypted_data.decode())

    shares = [tuple(pair) for pair in data["shares"]]
    pw = data["pw"]

    return shares, pw

def random_int():
    return random.randint(0, PRIME - 1)

def add_mod(a, b):
    return (a + b) % PRIME

def in_exponent(value):
    return pow(g, value, PRIME)

def generate_polynomial(secret, t):
    return [secret] + [random.randint(0, PRIME - 1) for _ in range(t - 1)]

def evaluate_polynomial(coefficients, x):
    result = 0
    for i, coef in enumerate(coefficients):
        result += coef * (x ** i) % PRIME
    return result % PRIME

def create_shares(secret, n, t):
    coefficients = generate_polynomial(secret, t)
    shares = [evaluate_polynomial(coefficients, x + 1) for x in range(n)]  # x = index + 1
    return shares

def lagrange_coefficient(x_vals, i):
    coeff = 1
    for j in range(len(x_vals)):
        if i != j:
            numerator = (x_vals[j]) % PRIME
            denominator = (x_vals[j] - x_vals[i] ) % PRIME
            coeff = coeff * numerator * mod_inverse(denominator, PRIME) % PRIME
    return coeff

def reconstruct_secret(shares, t, e):
    n = len(shares)
    seen = defaultdict(int)

    for indices in itertools.combinations(range(n), t + e):
        try:
            x_vals = [i + 1 for i in indices]
            y_vals = [shares[i] for i in indices]

            secret = 0
            for i in range(len(indices)):
                lag_coeff = lagrange_coefficient(x_vals, i)
                secret += y_vals[i] * lag_coeff
                secret %= PRIME

            seen[secret] += 1
            # Return early if a value dominates
            if seen[secret] >= e + 2:  # adjustable threshold
                return secret
        except Exception:
            continue

    if seen:
        return max(seen, key=seen.get)
    return None

def lagrange_coefficient_exponent(x_vals, i):
    coeff = 1
    for j in range(len(x_vals)):
        if i != j:
            numerator = x_vals[j]
            denominator = (x_vals[j] - x_vals[i] ) % (PRIME - 1)
            coeff = coeff * numerator * mod_inverse(denominator, PRIME - 1) %  (PRIME - 1)
    return coeff % (PRIME - 1)

# TODO: make the exponent work
def reconstruct_secret_exponent(shares, t, e):
    n = len(shares)
    seen = defaultdict(int)

    # Iterate over combinations of t + e shares
    for indices in itertools.combinations(range(n), t + e):
        try:
            x_vals = [i + 1 for i in indices]  # Indices (1-based)
            y_vals = [shares[i] for i in indices]  # Corresponding shares (g^s_i)

            # Reconstruct the secret using Lagrange interpolation on shares (g^s_i)
            secret = 1  # Start with identity element (g^0 = 1)
            for i in range(len(indices)):
                lag_coeff = lagrange_coefficient_exponent(x_vals, i)  # Lagrange coefficient at x=0
                print(f"Lagrange coefficient for index {i}: {lag_coeff}")
                value = pow(y_vals[i], lag_coeff, PRIME)
                print(f"Value: {value}")
                secret = (secret * value) % PRIME  # Multiply by g^s_i^lambda_i

            # We track the most frequent reconstructed secret
            print(f"Reconstructed secret: {secret}")
            seen[secret] += 1

            # Return early if a value dominates
            if seen[secret] >= e + 2:  # adjustable threshold
                return secret  # Return g^secret

        except Exception:
            print("Failed to reconstruct secret.")
            continue

    # Return the most frequent reconstructed secret if found
    if seen:
        return max(seen, key=seen.get)

    return None


# Example usage
if __name__ == "__main__":
    secret = 1234567  # Example secret
    n = 12  # Total number of shares
    t = 9  # Threshold
    e = 1   # Tolerated errors

    shares = create_shares(secret, n, t)
    print("Shares:", shares)

    # Reconstruct the secret using t + 2e shares
    print ("Reconstruct with,  ", shares[:5] + [0] + shares[6:])
    reconstructed_secret1 =reconstruct_secret([0] + shares[1:], t, e)
    reconstructed_secret2 = reconstruct_secret(shares[:t + 2 * e], t, e)
    reconstructed_secret3 = reconstruct_secret(shares[:10]  + [0], t, e)
    reconstructed_secret4 = reconstruct_secret(shares[:9]  + [0]*2, t, e)
    reconstructed_secret5 = reconstruct_secret(shares[:5] + [0] + shares[6:] , t, e)
    print("Reconstructed Secret:", reconstructed_secret1, reconstructed_secret2, reconstructed_secret3, reconstructed_secret4, reconstructed_secret5)

    print("=========================")

    n = 64
    e = 8
    t = n - 2 * e - 1  # -1 necessary for the reed solomon codes to work
    k = random_int()
    print(f"secret: {k}")
    session_key_shares = create_shares(k, n, t)
    print(f"session_key_shares: {session_key_shares}")
    reconstructed_secret6 = reconstruct_secret(session_key_shares, t, e)
    print(f"Reconstructed Secret:", reconstructed_secret6)

    print("=========================")

    # exp_k = in_exponent(k)
    # print(f"session Key: {exp_k}")
    # session_key_shares = [in_exponent(s) for s in session_key_shares]
    # print(f"Shares: {session_key_shares}")
    # reconstructed_secret7 = reconstruct_secret_exponent(session_key_shares, t, e)
    # print("Reconstructed Secret:", reconstructed_secret7)
