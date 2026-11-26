"""Robust secret sharing (Shamir with error correction) carried out "in the exponent".

Shares are generated in Z_q. Reconstruction takes exponentiated shares g^{s_i} in Z_p
and recovers g^{secret} by Lagrange interpolation in the exponent. Up to ``e`` wrong
shares are tolerated by trying every subset of size ``t`` and taking a strict majority.
"""

from collections import defaultdict
from dataclasses import dataclass
from fractions import Fraction
from functools import cache
from itertools import combinations
from math import gcd, lcm

from fapake.modmath import ModularArithmetic


def _lagrange_at_zero(xs: tuple[int, ...], i: int) -> Fraction:
    result = Fraction(1)
    for j, xj in enumerate(xs):
        if j != i:
            result *= Fraction(xj, xj - xs[i])
    return result


@cache
def _integer_lagrange_table(m: int, t: int) -> tuple[int, list[tuple[tuple[int, ...], list[int]]]]:
    """Lagrange coefficients (at 0) for every t-subset of x = 1..m, scaled to integers.

    The coefficients are small fractions. Multiplying them all by one common
    denominator D turns them into small integers, so interpolating in the exponent
    costs t cheap exponentiations per subset instead of t full-size ones. The result
    is g^{D*secret}; one final exponentiation by D^{-1} mod q removes D.
    """
    subsets = list(combinations(range(1, m + 1), t))
    fractions = [[_lagrange_at_zero(xs, i) for i in range(t)] for xs in subsets]
    D = lcm(*(f.denominator for row in fractions for f in row))
    return D, [(xs, [int(f * D) for f in row]) for xs, row in zip(subsets, fractions)]


@dataclass(frozen=True)
class Vote:
    """The value one t-subset of shares interpolates to (scaled by D, see votes())."""

    xs: tuple[int, ...]
    value: int


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

        votes = self.votes(shares)
        if not votes:
            return None
        counts = defaultdict(int)
        for vote in votes:
            counts[vote.value] += 1
        most_common, count = max(counts.items(), key=lambda item: item[1])
        if list(counts.values()).count(count) > 1:
            return None
        return self.unscale(most_common, len(shares))

    def votes(self, shares: list[int]) -> list[Vote]:
        """Interpolate every usable t-subset of the shares. One Vote per subset.

        Vote values are scaled (g^{D·secret}); equal values mean equal secrets.
        Use unscale() to turn one into g^{secret}.
        """
        if len(shares) < self.t:
            return []
        p = self.Math.PRIME
        _, table = _integer_lagrange_table(len(shares), self.t)

        # A multiple of p is not a group element, so it cannot be an honest share. It must not
        # take part in any vote: 0^c = 0 would make every subset containing it agree on 0.
        invalid = {x for x, y in enumerate(shares, start=1) if y % p == 0}

        votes = []
        for xs, coefficients in table:
            if invalid.intersection(xs):
                continue
            value = 1  # ∏ y_i^(λ_i·D) mod p = g^(D·secret) for honest shares
            for x, c in zip(xs, coefficients):
                value = value * pow(shares[x - 1], c, p) % p
            votes.append(Vote(xs, value))
        return votes

    def unscale(self, value: int, share_count: int) -> int:
        """Turn a vote value g^{D·secret} back into g^{secret}."""
        D, _ = _integer_lagrange_table(share_count, self.t)
        q = self.Math.sub_PRIME
        if gcd(D, q) != 1:
            raise ValueError("subgroup order too small for these parameters")
        return pow(value, pow(D, -1, q), self.Math.PRIME)

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
