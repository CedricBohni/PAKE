import random
from sympy import mod_inverse


# p =  47 # needs to be kq+1
# q = 23
# g= 25
p = 209459
q = 104729
g = 4
# p = 53919893334301279589334030174039261347115832520052616287020132597763
# q = 26959946667150639794667015087019630673557916260026308143510066298881
# g = 4
class ModularArithmetic:

    def __init__(self, generator: int = g, PRIME: int = p, sub_PRIME: int=q) -> None:

        self.generator = generator
        self.PRIME = PRIME
        self.sub_PRIME = q

    def mod(self, a: int, sub: bool = False) -> int:
        if sub:
            return a % self.sub_PRIME
        else:
            return a % self.PRIME

    def generate_random_int(self, sub: bool = False) -> int:
        if sub:
            return random.randint(1, (self.sub_PRIME - 1))
        else:
            return random.randint(1, (self.PRIME - 1))

    def modular_generator_exponentiation(self, value: int, sub: bool = False) -> int:
        if sub:
            return pow(self.generator, value, self.sub_PRIME)
        else:
            return pow(self.generator, value, self.PRIME)

    def modular_exponentiation(self, base: int, exponent: int, sub: bool = False) -> int:
        if sub:
            return pow(base, exponent, self.sub_PRIME)
        else:
            return pow(base, exponent, self.PRIME)

    def modular_inverse(self, a: int, sub: bool = False) -> int:
        if sub:
            return mod_inverse(a, self.sub_PRIME)
        else:
            return mod_inverse(a, self.PRIME)

    def modular_addition(self, a: int, b: int, sub: bool = False) -> int:
        if sub:
            return (a + b) % self.sub_PRIME
        else:
            return (a + b) % self.PRIME

    def modular_subtraction(self, a: int, b: int, sub: bool = False) -> int:
        if sub:
            return (a - b) % self.sub_PRIME
        else:
            return (a - b) % self.PRIME

    def modular_multiplication(self, a: int, b: int, sub: bool = False) -> int:
        if sub:
            return (a * b) % self.sub_PRIME
        else:
            return (a * b) % self.PRIME

    def modular_division(self, a: int, b: int, sub: bool = False) -> int:
        if sub:
            return self.modular_multiplication(a, self.modular_inverse(b, sub=True), sub=True)
        else:
            return self.modular_multiplication(a, self.modular_inverse(b))

    def pseudo_random_generator(self, seed, sub: bool = False):
        if sub:
            value = pow(self.generator, seed, self.sub_PRIME)
        else:
            value = pow(self.generator, seed, self.PRIME)

        output = value.to_bytes((value.bit_length() + 7) // 8, 'big')

        return output.hex()

