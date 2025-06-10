from utils.Math import ModularArithmetic
from collections import defaultdict
from itertools import combinations

class RobustSecretSharing:
    """
        A class implementing Robust Secret Sharing (RSS) with error correction in the context of exponentiation.
    """

    def __init__(self, n: int, t: int, e: int) -> None:
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
        self.Math = ModularArithmetic()

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
        Reconstructs the secret from the given shares, handling errors if possible.

        The method uses Lagrange interpolation in the context of modular arithmetic to reconstruct the secret.
        It iterates over all possible subsets of shares of size `t`, computes the secret for each subset,
        and keeps track of the most frequently reconstructed secret to handle errors.
        """

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
                secret = 1
                for i in range(self.t):
                    lagrange_coeff = self.lagrange_coefficient(list(x_values), i) # in mod q
                    g_term =  self.Math.modular_exponentiation(y_values[i], lagrange_coeff) # y_i^λ_i mod p
                    secret = self.Math.modular_multiplication(secret,g_term) # ∏(y_i^λ_i) mod p
                secret = self.Math.mod(secret)
                seen[secret] += 1
            except Exception as e:
                print("Error in reconstruction:", e)
                continue
        if seen:
            most_common = max(seen.items(), key=lambda x: x[1])
            if list(seen.values()).count(most_common[1]) > 1:
                print("No unique most common secret found.")
                return None
            return most_common[0]

        return None

    def lagrange_coefficient(self, x_values: list[int], i: int) -> int:
        """
        Computes the Lagrange coefficient for a given index `i` in the interpolation process.
        """
        result = 1
        for j in range(len(x_values)):
            if i != j:
                num = self.Math.mod(x_values[j], sub=True) # x_j mod q
                denom = self.Math.modular_subtraction(x_values[j], x_values[i], sub=True) # x_j - x_i mod q
                term = self.Math.modular_division(num, denom, sub=True) # x_j / (x_j - x_i) mod q
                result = self.Math.modular_multiplication(result, term, sub=True)
        return result

if __name__ == "__main__":
    # n = 16
    # t = 12
    # e = 2
    n = 8
    t = 6
    e = 1

    RSS = RobustSecretSharing(n, t, e)
    secret_original = RSS.Math.generate_random_int(sub=True)
    shares_original = RSS.generate_shares(secret_original)

    secret = RSS.Math.modular_generator_exponentiation(secret_original)
    shares = []
    for i in range(len(shares_original)):
        shares.append(RSS.Math.modular_generator_exponentiation(shares_original[i]))

    print(f"secret:         ", secret_original)
    print("Exponent Secret: ", secret)
    print("Shares:          ", shares_original)
    print("exponent Shares: ", shares)

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

    print("9. ✅ Randomize shares and reconstruct secret")
    random_secret = RSS.Math.generate_random_int(sub=True)
    print("random secret: ", random_secret)

    random_shares = RSS.generate_shares(random_secret)
    exponent_random_shares = []
    for i in range(len(random_shares)):
        exponent_random_shares.append(RSS.Math.modular_generator_exponentiation(random_shares[i]))

    exponent_random_secret = RSS.Math.modular_generator_exponentiation(random_secret)

    reconstruct_secret = RSS.reconstruct_secret(exponent_random_shares)
    print("exponent random secret: ", exponent_random_secret)
    print("Reconstructed random Secret: ", reconstruct_secret)

    added_secret = RSS.Math.modular_multiplication(secret, exponent_random_secret)
    print("added secret: ", added_secret)

    added_share = []
    for i in range(len(shares)):
        added_share.append(RSS.Math.modular_multiplication(shares[i] , RSS.Math.modular_generator_exponentiation(random_shares[i])))

    reconstruct_secret = RSS.reconstruct_secret(added_share)
    print("Reconstructed Secret: ", reconstruct_secret)



