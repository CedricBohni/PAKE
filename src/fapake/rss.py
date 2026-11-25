"""Robust secret sharing (Shamir with error correction) carried out "in the exponent".

Shares are generated in Z_q. Reconstruction takes exponentiated shares g^{s_i} in Z_p
and recovers g^{secret} by Lagrange interpolation in the exponent. Up to ``e`` wrong
shares are tolerated by trying every subset of size ``t`` and taking a strict majority.
"""

from collections import defaultdict
from itertools import combinations

from fapake.modmath import ModularArithmetic


class RobustSecretSharing:
    """
        A class implementing Robust Secret Sharing (RSS) with error correction in the context of exponentiation.
    """

    def __init__(self, n: int, t: int, e: int, math: ModularArithmetic | None = None) -> None:
        """
        Initializes the RobustSecretSharing instance.
        Args:
            n (int): Total number of shares.
            t (int): Threshold number of shares required to reconstruct the secret.
            e (int): Maximum number of erroneous shares that can be tolerated.
        """
        self.n = n
        self.t = t
        self.e = e
        self.Math = math or ModularArithmetic()

    def generate_shares(self, secret: int) -> list[int]:
        """
        Generates `n` shares for the given secret using a polynomial of degree `t-1`.
        """
        secret = self.Math.mod(secret, sub=True)
        polynomial_coefficients = [secret] + [self.Math.generate_random_int(sub=True) for _ in range(self.t - 1)]
        return [self.evaluate_polynomial(polynomial_coefficients, x) for x in range(1, self.n + 1)]

    def evaluate_polynomial(self, coefficients: list[int], x: int) -> int:
        """
        Evaluates a polynomial at a given x-coordinate.
        """
        result = 0
        for i, coefficient in enumerate(coefficients):
            result = self.Math.mod(result + coefficient * self.Math.modular_exponentiation(x, i, sub=True), sub=True)
        return result

    def reconstruct_secret(self, shares: list[int]) -> int | None:
        """
        Reconstructs g^secret from exponentiated shares, correcting errors where possible.

        Every subset of `t` shares is interpolated in the exponent; the value produced by
        the most subsets wins. Returns None if there are fewer than `t` shares or if no
        single value has a strict majority.
        """

        if len(shares) < self.t:
            return None

        seen = defaultdict(int)
        points = list(zip(range(1, len(shares) + 1), shares))

        for subset in combinations(points, self.t):
            x_values, y_values = zip(*subset)
            secret = 1
            for i in range(self.t):
                lagrange_coeff = self.lagrange_coefficient(list(x_values), i)  # in mod q
                g_term = self.Math.modular_exponentiation(y_values[i], lagrange_coeff)  # y_i^λ_i mod p
                secret = self.Math.modular_multiplication(secret, g_term)  # ∏ y_i^λ_i mod p
            seen[secret] += 1

        most_common, count = max(seen.items(), key=lambda item: item[1])
        if list(seen.values()).count(count) > 1:
            return None
        return most_common

    def lagrange_coefficient(self, x_values: list[int], i: int) -> int:
        """
        Computes the Lagrange coefficient (evaluated at 0) for index `i`.
        """
        result = 1
        for j in range(len(x_values)):
            if i != j:
                num = self.Math.mod(x_values[j], sub=True)  # x_j mod q
                denom = self.Math.modular_subtraction(x_values[j], x_values[i], sub=True)  # x_j - x_i mod q
                term = self.Math.modular_division(num, denom, sub=True)  # x_j / (x_j - x_i) mod q
                result = self.Math.modular_multiplication(result, term, sub=True)
        return result
