import Math
import random
from collections import defaultdict
from itertools import combinations

class RobustSecretSharing:
    def __init__(self, n: int, t: int, e: int) -> None:
        """
        Initialize the RSS (Robust Secret Sharing) instance.

        Args:
            n (int): Total number of shares.
            t (int): Minimum number of shares required to reconstruct the secret.
            e (int): Number of errors tolerated.
        """
        self.n = n
        self.t = t
        self.e = e
        self.Math = Math.ModularArithmetic()

    def generate_shares(self, secret: int) -> list[int]:
        """
        Generate shares for the given secret.

        Args:
            secret (int): The secret to be shared.

        Returns:
            list[int]: A list of shares.
        """
        secret = self.Math.mod(secret)
        # s + a_1*x + a_2*x^2 + ... + a_(t-1)*x^(t-1)
        polynomial_coefficients = [secret] + [self.Math.generate_random_int() for _ in range(self.t - 1)]
        return [self.evaluate_polynomial(polynomial_coefficients, x) for x in range(1, self.n + 1)]

    def evaluate_polynomial(self, coefficients: list[int], x: int) -> int:
        """
        Evaluate a polynomial at a given x value.

        Args:
            coefficients (list[int]): Coefficients of the polynomial.
            x (int): The x value to evaluate the polynomial at.

        Returns:
            int: The result of the polynomial evaluation modulo PRIME.
        """
        result = 0
        for i, coefficient in enumerate(coefficients):
            result = self.Math.mod(result + coefficient * self.Math.modular_exponentiation(x, i))
        return result

    def reconstruct_secret(self, shares: list[int]) -> int | None:
        """
        Reconstruct the secret from the given shares using error-tolerant methods.

        Args:
            shares (list[int]): A list of shares.

        Returns:
            int | None: The reconstructed secret, or None if reconstruction fails.
        """
        # Ensure there are enough shares to attempt reconstruction
        if len(shares) < self.t:
            print(f"Not enough shares. At least {self.t} shares are required.")
            return None

        seen = defaultdict(int)

        # Use a greedy sliding window approach to attempt reconstruction
        for _ in range(100):  # Try 100 random samples to improve performance
            random_indices = random.sample(range(len(shares)), self.t)
            try:
                x_values = [i + 1 for i in random_indices]  # x-values for the shares (indices + 1)
                y_values = [shares[i] for i in random_indices]  # y-values (share values)

                secret = 0
                for i in range(len(random_indices)):
                    lagrange_coeff = self.lagrange_coefficient(x_values, i)
                    secret = self.Math.modular_addition(secret, self.Math.modular_multiplication(y_values[i], lagrange_coeff))

                # Store the reconstructed secret for each valid combination of shares
                seen[secret] += 1
            except Exception:
                continue

        if seen:
            # Return the most frequent reconstruction (the correct one)
            return max(seen.items(), key=lambda x: x[1])[0]

        return None  # Return None if no valid reconstruction found

    def lagrange_coefficient(self, x_values: list[int], i: int) -> int:
        """
        Compute the Lagrange coefficient for a given index.

        Args:
            x_values (list[int]): The x values of the shares.
            i (int): The index for which to compute the coefficient.

        Returns:
            int: The Lagrange coefficient modulo PRIME.
        """
        coefficient = 1
        for j in range(len(x_values)):
            if i != j:
                coefficient = self.Math.modular_multiplication(coefficient, self.Math.modular_division(self.Math.mod(x_values[j]), self.Math.modular_subtraction(x_values[j], x_values[i])))
        return coefficient

if __name__ == "__main__":
    # 8: n = 64 6: n = 48
    n = 24
    t = 10 + 1
    e = 3
    # 3*6 + 3 =
    RSS = RobustSecretSharing(n, t, e)
    # need >= t + 2*e for reconstruction if e errors
    shares = RSS.generate_shares(10)

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
    used_shares = [1]*e + shares[e:t+e]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("5. ✅ Reconstruct with e error shares t honest shares so that  >= t + 2*e")
    used_shares = [1]*e + shares[e:t+e]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("6. ❌ Reconstruct with too many e error shares")
    used_shares = [1]*e + shares[e:n-1] + [0]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("7. ✅ Reconstruct with e error shares")
    used_shares = [1] * e + shares[e:]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("8. ✅ Reconstruct with e error shares")
    used_shares = shares[0:n-e] + [1] * e
    print(f"number of shares: {len(used_shares)}")
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)