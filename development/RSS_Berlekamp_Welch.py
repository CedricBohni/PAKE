from fapake.modmath import ModularArithmetic
from sympy import Matrix, symbols, Poly, div
from sympy.abc import x as x_sympy

class RobustSecretSharing:

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

        # sufficient shares
        if len(shares) < self.t:
            print(f"Not enough shares. At least {self.t} shares are required.")
            return None

        # prepare the points
        x_values = list(range(1, self.n + 1))
        points = list(zip(x_values, shares))

        # polynomial degrees
        q_degree = t + self.e - 1
        e_degree = self.e

        # linear systems
        num_unknowns = q_degree + 1 + e_degree
        A = []
        b = []

        for xi, yi in points:
            row = []

            # Q(xi) terms: xi^0 ... xi^q_degree
            for i in range(q_degree + 1):
                row.append(self.Math.modular_exponentiation(xi, i))

            # E(xi) terms: (-yi) * xi^1 ... xi^e_degree
            for i in range(1, e_degree + 1):
                term = self.Math.modular_multiplication((-yi) , self.Math.modular_exponentiation(xi, i))
                row.append(term)

            A.append([self.Math.mod(x) for x in row])
            b.append(self.Math.mod(yi))  # yi * E0 (E0 assumed 1)

        # Solve the system A * vars = b mod p
        M = Matrix(A)
        b_vec = Matrix(b)

        try:
            sol, params = M.gauss_jordan_solve(b_vec)

            # handle underdetermined systems
            if params.shape == (0, 0):
                solution = [self.Math.mod(int(s)) for s in sol]
            else:
                # Underdetermined: fill free variables with 0
                print("Underdetermined system. Using free variables = 0.")
                zero_free_params = Matrix.zeros(params.shape[1], 1)  # shape (num_free_vars, 1)
                solution_vec = sol + params @ zero_free_params
                solution = [self.Math.mod(int(s)) for s in solution_vec]

        except Exception as e:
            print(f"Linear system solve failed: {e}")
            return None

        # Extract Q and E coefficients
        q_coeffs = [self.Math.mod(int(solution[i])) for i in range(q_degree + 1)]
        e_coeffs = [1] + [self.Math.mod(int(solution[i])) for i in range(q_degree + 1, num_unknowns)]

        Q = Poly.from_list(q_coeffs[::-1], gens=x_sympy, domain=f'GF({self.Math.PRIME})')
        E = Poly.from_list(e_coeffs[::-1], gens=x_sympy, domain=f'GF({self.Math.PRIME})')
        f, r = div(Q, E, domain=f'GF({self.Math.PRIME})')

        if r != 0:
            print("Non-zero remainder — cannot reconstruct unique polynomial.")
            return None

        # Secret is f(0)
        secret = f.eval(0)
        print(f"Recovered secret: {secret}")
        return int(secret)

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
