"""1-out-of-2 oblivious transfer based on RSA (Even-Goldreich-Lempel style).

Each round:
    1. Sender publishes two random values x0, x1.
    2. Receiver with choice bit b picks random k and sends v = x_b + k^e mod N.
    3. Sender computes k_j = (v - x_j)^d for j in {0, 1} and returns
       c_j = m_j + k_j mod N. Only k_b equals the receiver's k.
    4. Receiver recovers m_b = c_b - k. The other message stays hidden.

The sender never learns b, and the receiver learns only m_b. Messages must be
smaller than N.
"""

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa

Rand = Callable[[], int]


@dataclass(frozen=True)
class RSAPublicKey:
    N: int
    e: int


@dataclass(frozen=True, repr=False)
class RSAKeyPair:
    N: int
    e: int
    d: int
    # Optional prime factors of N; when present, private operations use the CRT (~3x faster).
    prime1: int | None = None
    prime2: int | None = None

    def __post_init__(self) -> None:
        if (self.prime1 is None) != (self.prime2 is None):
            raise ValueError("give both prime factors or neither")
        if self.prime1 is not None and self.prime1 * self.prime2 != self.N:
            raise ValueError("prime factors do not multiply to N")

    @property
    def public(self) -> RSAPublicKey:
        return RSAPublicKey(self.N, self.e)

    def private_power(self, c: int) -> int:
        """c^d mod N."""
        if self.prime1 is None:
            return pow(c, self.d, self.N)
        p, q = self.prime1, self.prime2
        m1 = pow(c, self.d % (p - 1), p)
        m2 = pow(c, self.d % (q - 1), q)
        h = pow(q, -1, p) * (m1 - m2) % p
        return m2 + h * q

    def __repr__(self) -> str:  # keep private values out of logs and tracebacks
        return f"RSAKeyPair(N=<{self.N.bit_length()} bits>, e={self.e}, d=<hidden>)"


def generate_key(bits: int = 3072) -> RSAKeyPair:
    """Generate a fresh RSA key pair for oblivious transfer."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    numbers = private.private_numbers()
    return RSAKeyPair(numbers.public_numbers.n, numbers.public_numbers.e, numbers.d,
                      numbers.p, numbers.q)


def key_bits_for(modulus: int) -> int:
    """RSA size (multiple of 1024, at least 1024) whose N is always larger than `modulus`."""
    return max(1024, (modulus.bit_length() // 1024 + 1) * 1024)


def _uniform_below(N: int) -> Rand:
    return lambda: secrets.randbelow(N - 1) + 1


@dataclass(frozen=True)
class OTOffer:
    """The sender's random values for the next round."""
    x0: int
    x1: int


@dataclass(frozen=True)
class OTReply:
    """The sender's masked messages plus the offer for the following round."""
    c0: int
    c1: int
    next_offer: OTOffer


class OTSender:
    def __init__(self, key: RSAKeyPair, rand: Rand | None = None) -> None:
        self.key = key
        self._rand = rand or _uniform_below(key.N)
        self.offer = self._new_offer()

    def _new_offer(self) -> OTOffer:
        return OTOffer(self._rand(), self._rand())

    def respond(self, v: int, m0: int, m1: int) -> OTReply:
        N = self.key.N
        if not (0 <= m0 < N and 0 <= m1 < N):
            raise ValueError("OT messages must be smaller than N")
        k0 = self.key.private_power((v - self.offer.x0) % N)
        k1 = self.key.private_power((v - self.offer.x1) % N)
        self.offer = self._new_offer()
        return OTReply((m0 + k0) % N, (m1 + k1) % N, self.offer)


class OTReceiver:
    def __init__(self, key: RSAPublicKey, rand: Rand | None = None) -> None:
        self.key = key
        self._rand = rand or _uniform_below(key.N)
        self._k: int | None = None
        self._choice: int | None = None

    def query(self, offer: OTOffer, choice: int) -> int:
        if choice not in (0, 1):
            raise ValueError("choice must be 0 or 1")
        self._k = self._rand()
        self._choice = choice
        x = offer.x0 if choice == 0 else offer.x1
        return (x + pow(self._k, self.key.e, self.key.N)) % self.key.N

    def extract(self, c0: int, c1: int) -> int:
        if self._k is None:
            raise RuntimeError("query() must be called before extract()")
        c = c0 if self._choice == 0 else c1
        m = (c - self._k) % self.key.N
        self._k = self._choice = None
        return m
