import hashlib
import random

# 2048-bit safe prime (for simulation; use real safe prime in production)
SAFE_PRIME = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
                 '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
                 'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
                 'E485B576625E7EC6F44C42E9A63A36210000000000090563', 16)

# generator
GENERATOR = 0x2

def random_scalar():
    """Generate a random scalar in the range [1, p-1] where p is the safe prime."""
    return random.randint(0, SAFE_PRIME - 1)

def mod_exp(base, exp):
    """Perform modular exponentiation."""
    return pow(base, exp, SAFE_PRIME)

# needs an integer
def prg(value):
    if value.bit_length() > 256:
        raise ValueError("Value too large to convert to 32 bytes")
    return hashlib.sha256(value.to_bytes(32, 'big')).digest()