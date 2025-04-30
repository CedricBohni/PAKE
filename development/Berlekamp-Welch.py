from utils.utils import Math


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
        if len(shares) < self.t + 2 * self.e:
            print(f"Not enough shares. At least {self.t + 2 * self.e} shares are required.")
            return None

        equations = []

        for x, y in zip(range(1, len(shares) + 1), shares):
            row = []

            # Terms for Q(x)
            for power in range(self.t + self.e):
                row.append(self.Math.modular_exponentiation(x, power))

            # Terms for E(x), multiply by -y
            for power in range(self.e):
                row.append(self.Math.modular_multiplication(-y, self.Math.modular_exponentiation(x, power)))

            # RHS (constant term)
            rhs = self.Math.modular_multiplication(y, self.Math.modular_exponentiation(x, self.e))

            row.append(rhs)
            equations.append(row)

        # Solve the system properly
        solution = self.solve_system(equations)

        if solution is None:
            print("System could not be solved.")
            return None

        # First t coefficients correspond to f(x)
        f_coeffs = solution[:self.t]

        # Secret is f(0), meaning constant term
        return f_coeffs[0]

    def solve_system(self, equations: list[list[int]]) -> list[int] | None:
        """
        Solve a linear system modulo PRIME using Gaussian elimination.

        Args:
            equations (list[list[int]]): augmented matrix [A|b]

        Returns:
            list[int]: solution vector
        """
        n = len(equations)
        m = len(equations[0]) - 1  # number of unknowns

        for i in range(m):
            # Find pivot
            pivot_row = None
            for r in range(i, n):
                if equations[r][i] != 0:
                    pivot_row = r
                    break

            if pivot_row is None:
                continue  # No pivot in this column, move to next

            # Swap rows
            equations[i], equations[pivot_row] = equations[pivot_row], equations[i]

            # Normalize pivot row
            inv = self.Math.modular_inverse(equations[i][i])
            for j in range(i, m + 1):
                equations[i][j] = self.Math.modular_multiplication(equations[i][j], inv)

            # Eliminate other rows
            for r in range(n):
                if r != i and equations[r][i] != 0:
                    factor = equations[r][i]
                    for j in range(i, m + 1):
                        temp = self.Math.modular_multiplication(factor, equations[i][j])
                        equations[r][j] = self.Math.modular_subtraction(equations[r][j], temp)

        # Extract solution
        solution = [0] * m
        for i in range(m):
            solution[i] = equations[i][m]

        return solution

    # def solve_system(self, equations: list[list[int]]) -> list[int]:
    #     n = len(equations)
    #     for i in range(n):
    #         # Make matrix[i][i] == 1
    #         inv = self.Math.modular_inverse(equations[i][i])
    #         for j in range(len(equations[i])):
    #             equations[i][j] = self.Math.modular_multiplication(equations[i][j], inv)
    #             print(equations[i][j])
    #
    #         # Eliminate other rows
    #         for k in range(n):
    #             if k != i:
    #                 factor = equations[k][i]
    #                 for j in range(len(equations[k])):
    #                     equations[k][j] = self.Math.modular_subtraction(equations[k][j], self.Math.modular_multiplication(factor, equations[i][j]))
    #
    #     # Extract solution
    #     return [row[-1] for row in equations]


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
    n = 32
    t = 16
    e = 4
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

    # print("4. ❌ Reconstruct with only t honest shares + e error shares")
    # used_shares = [0]*e + shares[e:t+e]
    # reconstruct_secret = RSS.reconstruct_secret(used_shares)
    # print("Reconstructed Secret: ", reconstruct_secret)

    # print("5. ✅ Reconstruct with e error shares t honest shares so that  >= t + 2*e")
    # used_shares = [0]*e + shares[e: (n-2*e)+e]
    # reconstruct_secret = RSS.reconstruct_secret(used_shares)
    # print("Reconstructed Secret: ", reconstruct_secret)

    # print("6. ❌ Reconstruct with too many e error shares")
    # used_shares = [0]*e + shares[e:n-1] + [0]
    # reconstruct_secret = RSS.reconstruct_secret(used_shares)
    # print("Reconstructed Secret: ", reconstruct_secret)

    print("7. ✅ Reconstruct with e error shares")
    used_shares = [0] * e + shares[e:]
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)

    print("8. ✅ Reconstruct with e error shares")
    used_shares = shares[0:n-e] + [0] * e
    print(f"number of shares: {len(used_shares)}")
    reconstruct_secret = RSS.reconstruct_secret(used_shares)
    print("Reconstructed Secret: ", reconstruct_secret)