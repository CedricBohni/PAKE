from crypto_utils import random_scalar, mod_exp, GENERATOR, SAFE_PRIME, prg
from shamir_rss import shamir_share

class Server:
    def __init__(self, pw_bits):
        self.pw_bits = pw_bits

    def prepare(self):
        n =len(self.pw_bits)
        t = 2
        k = random_scalar()
        shares = shamir_share(k, n, t, SAFE_PRIME)
        self.k = k
        self.k_prime = random_scalar()
        self.K = mod_exp(GENERATOR, k)
        self.file_blocks = []

        for i, bit in enumerate(self.pw_bits):
            r = random_scalar()
            a0 = mod_exp(GENERATOR, r)
            a1 = mod_exp(GENERATOR, shares[i][1])
            if bit == 0:
                self.file_blocks.append((a1, a0))
            else:
                self.file_blocks.append((a0, a1))

        gk = mod_exp(GENERATOR, k)
        K_prime = mod_exp(GENERATOR, self.k_prime)
        self.shared_key = prg(K_prime)
        return self.shared_key, self.file_blocks, self.k_prime