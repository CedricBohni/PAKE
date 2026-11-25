from fapake.modmath import ModularArithmetic
from collections import defaultdict
from itertools import combinations

class RobustSecretSharing:
    """
        A class implementing Robust Secret Sharing (RSS) with error correction.

        Attributes:
            n (int): Total number of shares.
            t (int): Threshold number of shares required to reconstruct the secret.
            e (int): Maximum number of erroneous shares that can be tolerated.

        Methods:
            generate_shares(secret: int) -> list[int]:
                Generates `n` shares for the given secret using a polynomial of degree `t-1`.

            evaluate_polynomial(coefficients: list[int], x: int) -> int:
                Evaluates a polynomial at a given x-coordinate.

            reconstruct_secret(shares: list[int]) -> int | None:
                Reconstructs the secret from the given shares, handling errors if possible.

            lagrange_coefficient(x_values: list[int], i: int) -> int:
                Computes the Lagrange coefficient for a given index `i` in the interpolation process.
    """

    def __init__(self, n: int, t: int, e: int) -> None:
        self.n = n
        self.t = t
        self.e = e
        self.Math = ModularArithmetic()

    def generate_shares(self, secret: int) -> list[int]:

        secret = self.Math.mod(secret)
        polynomial_coefficients = [secret] + [self.Math.generate_random_int() for _ in range(self.t - 1)]
        return [self.evaluate_polynomial(polynomial_coefficients, x) for x in range(1, self.n + 1)]

    def evaluate_polynomial(self, coefficients: list[int], x: int) -> int:

        result = 0
        for i, coefficient in enumerate(coefficients):
            result = self.Math.mod(result + coefficient * self.Math.modular_exponentiation(x, i))
        return result

    def reconstruct_secret(self, shares: list[int]) -> int | None:
        if len(shares) < self.t:
            print(f"Not enough shares. At least {self.t} shares are required.")
            return None

        seen = defaultdict(int)

        x_values = list(range(1, len(shares) + 1))
        shares = list(zip(x_values, shares))

        for subset in combinations(shares, self.t):
            x_values, y_values = zip(*subset)
            try:
                x_values, y_values = zip(*subset)
                secret = 0
                for i in range(self.t):
                    lagrange_coeff = self.lagrange_coefficient(list(x_values), i)
                    secret = self.Math.modular_addition(secret,
                                                        self.Math.modular_multiplication(y_values[i], lagrange_coeff))
                seen[secret] += 1
            except Exception:
                continue

        if seen:
            most_common = max(seen.items(), key=lambda x: x[1])
            if list(seen.values()).count(most_common[1]) > 1:
                print("No unique most common secret found.")
                return None
            print(f"Returning most common secret: {most_common[0]}, seen {most_common[1]} times.")
            print(f"I have seen; {len(seen)} different secrets.")
            return most_common[0]

        return None

    def lagrange_coefficient(self, x_values: list[int], i: int) -> int:
        coefficient = 1
        for j in range(len(x_values)):
            if i != j:
                coefficient = self.Math.modular_multiplication(coefficient, self.Math.modular_division(self.Math.mod(x_values[j]), self.Math.modular_subtraction(x_values[j], x_values[i])))
        return coefficient

if __name__ == "__main__":
    n = 16
    t = 13
    e = 2

    RSS = RobustSecretSharing(n, t, e)
    secret = RSS.Math.generate_random_int()
    print(f"secret: ", secret)
    shares = RSS.generate_shares(secret)

    print("=== Shares ===")
    print("Shares: ", shares)

    print("1. ✅ Reconstruct the secret from all shares")
    used_shares = shares
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("2. ❌ Reconstruct with <t insufficient shares")
    used_shares = shares[:t-1]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("3. ✅ Reconstruct with t honest shares")
    used_shares = shares[:t]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("4. ❌ Reconstruct with only t honest shares + e error shares")
    used_shares = [1 for i in range(e)] + shares[e:t+e]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)
    used_shares = shares[:t] + [1 for i in range(e)]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("5. ✅ Reconstruct with e error shares t honest shares so that  >= t + 2*e")
    used_shares = [1 for i in range(e)] + shares[e:t+(2*e)]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("6. ❌ Reconstruct with too many e error shares")
    used_shares = [1 for i in range(e)] + shares[e:n-1] + [1]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("7. ✅ Reconstruct with e error shares")
    used_shares = [1 for i in range(e)] + shares[e:]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("8. ✅ Reconstruct with e error shares")
    used_shares = shares[0:n-e] + [1 for i in range(e)]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("9. ✅ Reconstruct randomized shares")
    random_secret = RSS.Math.generate_random_int()
    print(f"random_secret: {random_secret}")
    random_shares = RSS.generate_shares(random_secret)
    new_secret = RSS.Math.modular_addition(secret, random_secret)
    print("new secret: ", new_secret)
    new_shares = [None] * n
    for i in range(len(random_shares)):
       new_shares[i] = RSS.Math.modular_addition(shares[i], random_shares[i])

    reconstruct_secret = RSS.reconstruct_secret(new_shares)
    print("Reconstructed Secret: ", reconstruct_secret)
