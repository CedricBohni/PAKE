"""1-out-of-2 oblivious transfer based on RSA (Even-Goldreich-Lempel style).

Each round:
    1. Sender publishes two random values x0, x1.
    2. Receiver with choice bit b picks random k and sends v = x_b + k^e mod N.
    3. Sender computes k_j = (v - x_j)^d for j in {0, 1} and returns
       c_j = m_j + k_j mod N. Only k_b equals the receiver's k.
    4. Receiver recovers m_b = c_b - k. The other message stays hidden.

The sender never learns b, and the receiver learns only m_b.
"""

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class RSAPublicKey:
    N: int
    e: int


@dataclass(frozen=True)
class RSAKeyPair:
    N: int
    e: int
    d: int

    @property
    def public(self) -> RSAPublicKey:
        return RSAPublicKey(self.N, self.e)


# Fixed demo key (512-bit). Not secure: the private exponent is public in this repo.
DEMO_KEY = RSAKeyPair(
    N=12000991551859018265872407496869639382864790287669785722210322332355258447403853342474429805696877488833857305762518590969878052344745850541503850065903633,
    e=65537,
    d=11862920727285087512672416724441244612053186889941738688709451327600755420573868763412620915039546779273239567721613654909753857882486728158879371802110993,
)


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
    def __init__(self, key: RSAKeyPair, rand: Callable[[], int]) -> None:
        self.key = key
        self._rand = rand
        self.offer = self._new_offer()

    def _new_offer(self) -> OTOffer:
        return OTOffer(self._rand(), self._rand())

    def respond(self, v: int, m0: int, m1: int) -> OTReply:
        N, d = self.key.N, self.key.d
        k0 = pow(v - self.offer.x0, d, N)
        k1 = pow(v - self.offer.x1, d, N)
        self.offer = self._new_offer()
        return OTReply((m0 + k0) % N, (m1 + k1) % N, self.offer)


class OTReceiver:
    def __init__(self, key: RSAPublicKey, rand: Callable[[], int]) -> None:
        self.key = key
        self._rand = rand
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
