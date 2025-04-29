import Math
from collections import Counter, defaultdict
import itertools

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
        result = coefficients[-1]
        # Horner's method
        for coeff in reversed(coefficients[:-1]):
            result = self.Math.mod(result * x + coeff)
        return result

    def reconstruct_secret(self, shares: list[int]) -> int | None:
        """
        Reconstruct the secret from the given shares.

        Args:
            shares (list[int]): A list of shares.

        Returns:
            int | None: The reconstructed secret, or None if reconstruction fails.
        """
        seen = defaultdict(int)

        for indices in itertools.combinations(range(len(shares)), self.t):
            try:
                x_values = [i + 1 for i in indices]
                y_values = [shares[i] for i in indices]

                secret = 0
                for i in range(len(indices)):
                    secret = self.Math.modular_addition(secret, self.Math.modular_multiplication(y_values[i], self.lagrange_coefficient(x_values, i)))

                seen[secret] += 1
            except Exception:
                continue

        if seen:
            return max(seen.items(), key=lambda x: x[1])[0]
        return 0

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
    RSS = RobustSecretSharing(12, 5, 1)
    # need >= t + 2*e for reconstruction if e errors
    shares = RSS.generate_shares(10)

    print("✅ Reconstruct the secret from all shares")
    used_shares = shares
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("❌ Reconstruct with <t insufficient shares")
    used_shares = shares[:4]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("✅ Reconstruct with t honest shares")
    used_shares = shares[:5]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("❌ Reconstruct with only t honest shares + e error shares")
    used_shares = [0] + shares[1:6]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("✅ Reconstruct with e error shares t honest shares so that  >= t + 2*e")
    used_shares = [0] + shares[1:7]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("❌ Reconstruct with t honest shares and too many e error shares")
    used_shares = [0] + shares[1:6] + [0]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    RSS = RobustSecretSharing(64, 48, 8)
    # t <= n - 2*e => 64 - 2*8 = 48
    shares = RSS.generate_shares(10)
    print("✅ Reconstruct the secret from all shares")
    used_shares = shares
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)