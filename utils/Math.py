import random
from sympy import mod_inverse

p_hex = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22
514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6
F44C42E9A63A3620FFFFFFFFFFFFFFFF
""".replace("\n", "").replace(" ", "")
p = int(p_hex, 16)
g= 2

class ModularArithmetic:
    """
    A class to perform modular arithmetic operations.

    Attributes:
        generator (int): The base value for modular exponentiation.
        PRIME (int): The prime modulus for arithmetic operations.
    """

    def __init__(self, generator: int = g, PRIME: int = p) -> None:
        """
        Initialize the ModularArithmetic instance.

        Args:
            generator (int): The base value for modular exponentiation.
            PRIME (int): The prime modulus for arithmetic operations.
        """
        self.generator = generator
        self.PRIME = PRIME

    def mod(self, a: int) -> int:
        """
        Ensure the integer is within the modular space.

        Args:
            a (int): The integer to be adjusted.

        Returns:
            int: The adjusted integer within the modular space.
        """
        return a % self.PRIME

    def generate_random_int(self) -> int:
        """
        Generate a random integer in the range [0, PRIME - 1].

        Returns:
            int: A random integer within the specified range.
        """
        return random.randint(1, (self.PRIME - 1))

    def modular_generator_exponentiation(self, value: int) -> int:
        """
        Compute the modular exponentiation of the generator raised to a value.

        Args:
            value (int): The exponent.

        Returns:
            int: The result of (generator^value) % PRIME.
        """
        return pow(self.generator, value, self.PRIME)

    def modular_exponentiation(self, base: int, exponent: int) -> int:
        """
        Compute modular exponentiation.

        Args:
            base (int): The base value.
            exponent (int): The exponent.

        Returns:
            int: The result of (base^exponent) % PRIME.
        """
        return pow(base, exponent, self.PRIME)

    def modular_inverse(self, a: int) -> int:
        """
        Compute the modular inverse of a number.

        Args:
            a (int): The number to find the inverse of.

        Returns:
            int: The modular inverse of a modulo PRIME.
        """
        return mod_inverse(a, self.PRIME)

    def modular_addition(self, a: int, b: int) -> int:
        """
        Perform modular addition.

        Args:
            a (int): The first operand.
            b (int): The second operand.

        Returns:
            int: The result of (a + b) % PRIME.
        """
        return (a + b) % self.PRIME


    def modular_subtraction(self, a: int, b: int) -> int:
        """
        Perform modular subtraction.

        Args:
            a (int): The first operand.
            b (int): The second operand.

        Returns:
            int: The result of (a - b) % PRIME.
        """
        return (a - b) % self.PRIME

    def modular_multiplication(self, a: int, b: int) -> int:
        """
        Perform modular multiplication.

        Args:
            a (int): The first operand.
            b (int): The second operand.

        Returns:
            int: The result of (a * b) % PRIME.
        """
        return (a * b) % self.PRIME

    def modular_division(self, a: int, b: int) -> int:
        """
        Perform modular division.

        Args:
            a (int): The numerator.
            b (int): The denominator.

        Returns:
            int: The result of (a / b) % PRIME.
        """
        return self.modular_multiplication(a, self.modular_inverse(b))

    def pseudo_random_generator(self, seed):
        """
            Representative Functionality representing the generation of a pseudo-random value using modular exponentiation.

            Args:
                seed (int): The seed value for the generator.

            Returns:
                str: A hexadecimal string representing the pseudo-random value.
        """

        value = pow(self.generator, seed, self.PRIME)
        output = value.to_bytes((value.bit_length() + 7) // 8, 'big')

        return output.hex()

