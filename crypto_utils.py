from sympy import symbols, mod_inverse
import itertools
from collections import Counter, defaultdict

p_hex = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22
514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6
F44C42E9A63A3620FFFFFFFFFFFFFFFF
""".replace("\n", "").replace(" ", "")

PRIME = int(p_hex, 16)
g = 2

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

