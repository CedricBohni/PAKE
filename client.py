from crypto_utils import mod_exp, SAFE_PRIME, prg

class Client:
    def __init__(self, pw_bits):
        self.pw_bits = pw_bits

    def receive(self, file_blocks, k_prime):
        self.file_blocks = file_blocks
        self.k_prime = k_prime