from collections import defaultdict
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
        result = 0
        for i, coefficient in enumerate(coefficients):
            result = self.Math.mod(result + coefficient * self.Math.modular_exponentiation(x, i))
        return result

    def reconstruct_secret(self, shares):
        n = len(shares)
        seen = defaultdict(int)

        for indices in itertools.combinations(range(n), t + e):
            try:
                x_vals = [i + 1 for i in indices]
                y_vals = [shares[i] for i in indices]

                secret = 0
                for i in range(len(indices)):
                    lag_coeff = self.lagrange_coefficient(x_vals, i)
                    secret += y_vals[i] * lag_coeff
                    secret = self.Math.mod(secret)

                seen[secret] += 1
                # Return early if a value dominates
                if seen[secret] >= e + 2:  # adjustable threshold
                    return secret
            except Exception:
                continue

        if seen:
            return max(seen, key=seen.get)
        return None

    def lagrange_coefficient(self, x_vals, i):
        coeff = 1
        for j in range(len(x_vals)):
            if i != j:
                numerator = self.Math.mod((x_vals[j]))
                denominator = self.Math.modular_subtraction(x_vals[j], x_vals[i])
                coeff = self.Math.modular_multiplication(coeff , numerator * self.Math.modular_inverse(denominator))
        return coeff

if __name__ == "__main__":
    n = 15
    t = 10
    e = 2
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
    used_shares = [1]*e + shares[e:n-1] + [1]
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