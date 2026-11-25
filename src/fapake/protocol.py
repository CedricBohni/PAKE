"""Fuzzy aPAKE protocol logic, independent of any transport.

Registration
    The server picks a secret k, splits it into n Shamir shares k_i, and stores for
    every password bit i the pair (g^{k_i}, g^{r_i}) ordered by that bit: the real
    share sits in the slot matching the bit, a random decoy in the other. It also
    stores g^k and g^pw.

Authentication
    1. The server re-randomizes: it picks a fresh secret r with shares r_i and
       multiplies g^{r_i} into both slots of every pair, giving K = g^{k+r}.
       It sends Enc_K(shares, g^pw) and starts n oblivious transfers.
    2. For each bit i the client obliviously fetches the slot selected by its own
       password bit. A correct bit yields a real share, a wrong bit a decoy.
    3. Robust reconstruction tolerates up to e decoys, so a password within
       Hamming distance e still recovers K.
    4. The client decrypts, checks g^pw is within distance e of its password and
       that the OT shares match the encrypted ones, and derives the session key.

On any failure the client outputs a random key, as an aPAKE does, so a wrong
password is indistinguishable from a right one until the key is used.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import combinations

from cryptography.exceptions import InvalidTag

from fapake.ic import decrypt, encrypt
from fapake.modmath import DEFAULT_GROUP, DEMO_GROUP, Group, ModularArithmetic
from fapake.ot import (OTOffer, OTReceiver, OTReply, OTSender, RSAKeyPair, RSAPublicKey,
                       generate_key, key_bits_for)
from fapake.rss import RobustSecretSharing

Password = list[int]


@dataclass(frozen=True)
class Params:
    """Protocol parameters. The password has n bits; up to e bit errors are tolerated."""
    n: int = 8
    t: int = 6
    e: int = 1
    group: Group = DEFAULT_GROUP

    def __post_init__(self) -> None:
        if not 0 < self.t <= self.n:
            raise ValueError("need 0 < t <= n")
        if self.t + 2 * self.e > self.n:
            raise ValueError("robust reconstruction needs t + 2e <= n")

    @property
    def ot_key_bits(self) -> int:
        return key_bits_for(self.group.p)

    def generate_ot_key(self) -> RSAKeyPair:
        """A fresh RSA key large enough to carry this group's elements through OT."""
        return generate_key(self.ot_key_bits)


DEFAULT_PARAMS = Params()
DEMO_PARAMS = Params(group=DEMO_GROUP)


class ProtocolError(Exception):
    """Raised for malformed input or messages that violate the protocol flow."""


def parse_password(text: str, length: int = DEFAULT_PARAMS.n) -> Password:
    """Turn a string like '10101010' into a list of bits, validating its form."""
    text = text.strip()
    if len(text) != length or any(c not in "01" for c in text):
        raise ProtocolError(f"password must be exactly {length} bits (0/1)")
    return [int(c) for c in text]


def validate_password(password: object, length: int) -> Password:
    if (not isinstance(password, list) or len(password) != length
            or any(isinstance(bit, bool) or bit not in (0, 1) for bit in password)):
        raise ProtocolError(f"password must be a list of {length} bits")
    return password


def password_to_int(password: Password) -> int:
    return int("".join(map(str, password)), 2)


def passwords_within_distance(password: Password, distance: int) -> list[Password]:
    """All passwords within the given Hamming distance, the original first."""
    result = [password[:]]
    for d in range(1, distance + 1):
        for positions in combinations(range(len(password)), d):
            candidate = password[:]
            for i in positions:
                candidate[i] ^= 1
            result.append(candidate)
    return result


def hamming_distance(a: Password, b: Password) -> int:
    return sum(x != y for x, y in zip(a, b))


def derive_session_key(shared_secret: int) -> str:
    """Session key as hex: SHA-256 of the shared group element, domain-separated
    from the AES key that ic.py derives from the same element."""
    return sha256(b"fapake session key|" + str(shared_secret).encode()).hexdigest()


def random_session_key() -> str:
    return secrets.token_hex(32)


# --------------------------------------------------------------------------- registration

@dataclass
class UserRecord:
    """What the server stores per user. Contains no plaintext password."""
    shares: list[tuple[int, int]]
    pw: int  # g^pw
    k: int   # g^k
    group: str = DEFAULT_GROUP.name

    def to_dict(self) -> dict:
        return {"group": self.group, "shares": [list(pair) for pair in self.shares],
                "pw": self.pw, "k": self.k}

    @classmethod
    def from_dict(cls, data: dict) -> UserRecord:
        return cls([tuple(pair) for pair in data["shares"]], data["pw"], data["k"],
                   data.get("group", DEMO_GROUP.name))  # records from before groups existed


@dataclass(frozen=True)
class RegistrationSecrets:
    """Values the server uses during registration and then forgets. Exposed for the visualizer."""
    k: int                       # the secret, in Z_q
    k_shares: list[int]          # Shamir shares of k, in Z_q
    decoy_exponents: list[int]   # r_i with decoy = g^{r_i}


def register_with_details(password: Password,
                          params: Params = DEFAULT_PARAMS) -> tuple[UserRecord, RegistrationSecrets]:
    """Like register(), but also returns the intermediate secrets."""
    validate_password(password, params.n)
    math = ModularArithmetic(params.group)
    rss = RobustSecretSharing(params.n, params.t, params.e, math)

    k = math.generate_random_int(sub=True)
    k_shares = rss.generate_shares(k)
    decoy_exponents = [math.generate_random_int(sub=True) for _ in password]

    shares: list[tuple[int, int]] = []
    for bit, k_share, decoy_exponent in zip(password, k_shares, decoy_exponents):
        real = math.modular_generator_exponentiation(k_share)
        decoy = math.modular_generator_exponentiation(decoy_exponent)
        shares.append((real, decoy) if bit == 0 else (decoy, real))

    record = UserRecord(
        shares=shares,
        pw=math.modular_generator_exponentiation(password_to_int(password)),
        k=math.modular_generator_exponentiation(k),
        group=params.group.name,
    )
    return record, RegistrationSecrets(k, k_shares, decoy_exponents)


def register(password: Password, params: Params = DEFAULT_PARAMS) -> UserRecord:
    """Create the server-side record for a password."""
    return register_with_details(password, params)[0]


# --------------------------------------------------------------------------- authentication

@dataclass(frozen=True)
class AuthChallenge:
    """The server's first authentication message."""
    group: str
    cipher: str  # JSON blob from ic.encrypt
    offer: OTOffer
    ot_key: RSAPublicKey


class ServerSession:
    """Server side of one authentication run."""

    def __init__(self, record: UserRecord, ot_key: RSAKeyPair, params: Params = DEFAULT_PARAMS) -> None:
        if record.group != params.group.name:
            raise ProtocolError(f"user was registered with group '{record.group}', "
                                f"server uses '{params.group.name}'")
        if ot_key.N <= params.group.p:
            raise ValueError("OT key modulus must be larger than the group prime")

        self.params = params
        self.math = ModularArithmetic(params.group)
        rss = RobustSecretSharing(params.n, params.t, params.e, self.math)

        r = self.math.generate_random_int(sub=True)
        r_shares = rss.generate_shares(r)
        self.r, self.r_shares = r, r_shares  # kept for inspection (visualizer, tests)
        self.randomized_key = self.math.modular_multiplication(
            record.k, self.math.modular_generator_exponentiation(r))

        self.shares: list[tuple[int, int]] = []
        for (zero, one), r_share in zip(record.shares, r_shares):
            mask = self.math.modular_generator_exponentiation(r_share)
            self.shares.append((self.math.modular_multiplication(zero, mask),
                                self.math.modular_multiplication(one, mask)))

        payload = json.dumps({"shares": [list(pair) for pair in self.shares], "pw": record.pw})
        self._cipher = encrypt(self.randomized_key, payload)
        self._ot_key = ot_key
        self._ot = OTSender(ot_key)
        self.requests = 0
        self.session_key = derive_session_key(self.randomized_key)

    def challenge(self) -> AuthChallenge:
        return AuthChallenge(self.params.group.name, self._cipher, self._ot.offer, self._ot_key.public)

    def respond_ot(self, index: int, v: int) -> OTReply:
        if self.requests >= self.params.n:
            raise ProtocolError("Too many requests")
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < self.params.n:
            raise ProtocolError("invalid share index")
        if not isinstance(v, int) or isinstance(v, bool):
            raise ProtocolError("invalid OT value")
        self.requests += 1
        m0, m1 = self.shares[index]
        return self._ot.respond(v, m0, m1)


@dataclass
class AuthResult:
    session_key: str
    ok: bool
    reasons: list[str] = field(default_factory=list)


class ClientSession:
    """Client side of one authentication run.

    Drive it with begin(challenge), then next_query/receive until done, then finish().
    """

    def __init__(self, password: Password, params: Params = DEFAULT_PARAMS) -> None:
        self.password = validate_password(password, params.n)
        self.params = params
        self.math = ModularArithmetic(params.group)
        self._rss = RobustSecretSharing(params.n, params.t, params.e, self.math)
        self._ot: OTReceiver | None = None
        self._cipher: str | None = None
        self.received: list[int] = []

    def begin(self, challenge: AuthChallenge) -> OTOffer:
        """Accept the server's challenge. Returns the offer for the first OT round."""
        if challenge.group != self.params.group.name:
            raise ProtocolError(f"server uses group '{challenge.group}', "
                                f"client uses '{self.params.group.name}'")
        if challenge.ot_key.N <= self.params.group.p:
            raise ProtocolError("server's OT key is too small for this group")
        self._ot = OTReceiver(challenge.ot_key)
        self._cipher = challenge.cipher
        return challenge.offer

    @property
    def done(self) -> bool:
        return len(self.received) == self.params.n

    def next_query(self, offer: OTOffer) -> tuple[int, int]:
        """Return (index, v) for the next oblivious transfer."""
        if self._ot is None:
            raise ProtocolError("begin() must be called first")
        if self.done:
            raise ProtocolError("all shares already received")
        index = len(self.received)
        return index, self._ot.query(offer, self.password[index])

    def receive(self, reply: OTReply) -> OTOffer:
        """Process an OT reply. Returns the offer for the next round."""
        self.received.append(self._ot.extract(reply.c0, reply.c1))
        return reply.next_offer

    def finish(self) -> AuthResult:
        if not self.done:
            raise ProtocolError("not all shares received")

        key = self._rss.reconstruct_secret(self.received)
        if key is None:
            return AuthResult(random_session_key(), False, ["reconstruction failed: too many wrong bits"])

        try:
            data = decrypt(key, json.loads(self._cipher))
        except (InvalidTag, ValueError, KeyError):
            return AuthResult(random_session_key(), False, ["decryption failed: wrong key"])

        reasons = []
        close = {self.math.modular_generator_exponentiation(password_to_int(pw))
                 for pw in passwords_within_distance(self.password, self.params.e)}
        if data["pw"] not in close:
            reasons.append("password is not within the allowed Hamming distance")

        if any(share != pair[bit] for share, pair, bit
               in zip(self.received, data["shares"], self.password)):
            reasons.append("shares from OT differ from the encrypted shares: file has been tampered with")

        if reasons:
            return AuthResult(random_session_key(), False, reasons)
        return AuthResult(derive_session_key(key), True)


def run_ot_rounds(server: ServerSession, client: ClientSession) -> None:
    """Exchange all OT rounds between two in-memory sessions."""
    offer = client.begin(server.challenge())
    while not client.done:
        index, v = client.next_query(offer)
        offer = client.receive(server.respond_ot(index, v))


def authenticate_locally(record: UserRecord, password: Password, params: Params = DEFAULT_PARAMS,
                         ot_key: RSAKeyPair | None = None) -> tuple[ServerSession, AuthResult]:
    """Run a full authentication in memory. Useful for tests, demos and benchmarks.

    Generating an OT key is slow for the default group, so pass one in when calling repeatedly.
    """
    server = ServerSession(record, ot_key or params.generate_ot_key(), params)
    client = ClientSession(password, params)
    run_ot_rounds(server, client)
    return server, client.finish()
