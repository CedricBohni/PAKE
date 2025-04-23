import random
from sympy import symbols, mod_inverse
import itertools
from collections import Counter

PRIME = 2**127 - 1

def random_share():
    return random.randint(0, PRIME - 1)

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

def lagrange_coefficient(x, x_vals, i):
    coeff = 1
    for j in range(len(x_vals)):
        if i != j:
            numerator = (x - x_vals[j]) % PRIME
            denominator = (x_vals[i] - x_vals[j]) % PRIME
            coeff = coeff * numerator * mod_inverse(denominator, PRIME) % PRIME
    return coeff

def reconstruct_secret(shares, t, e):
    n = len(shares)
    candidates = []
    for indices in itertools.combinations(range(n), t + e):
        try:
            x_vals = [i + 1 for i in indices]
            y_vals = [shares[i] for i in indices]

            secret = 0
            for i in range(len(indices)):
                lag_coeff = lagrange_coefficient(0, x_vals, i)
                secret += y_vals[i] * lag_coeff
                secret %= PRIME

            candidates.append(secret)
        except Exception:
            continue

    if not candidates:
        return None

    print(f"Candidates: {candidates}")

    return Counter(candidates).most_common(1)[0][0]

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


# Reed-Solomon parameters
# need n > t + 2e (t = threshold, e = tolerated errors)
# if we say each password can have maximum of one wrong letter and each share represents a bit
# a letter is 8 bits so we tolerate 8 errors
# we want at least 6 correct letters which is t = 6* 8 = 48
# so we need n > 48 + 2*8 = 64 => we need at least 65 shares => 7 letters
# approach:

# Share creation
# 1. choose random polynomial of degree t - 1 f(0) = s
# 2. create n many shares of (x, f(x))
#
# reconstruction
# 1. choose t + 2e shares
# 2. use Berlekamp-Welch algorithm to reconstruct the polynomial
# 3. evaluate the polynomial at x = 0 to get the secret

