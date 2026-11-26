"""Run one registration + authentication and record every intermediate value.

This drives the real protocol classes; it only observes them. The result is plain JSON
(big integers as strings, since JavaScript numbers can't hold them) and feeds the web
visualizer, but it is also handy for teaching and debugging:

    uv run python -m fapake.trace 10101010 10101011
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from typing import Literal

from fapake.modmath import GROUPS, ModularArithmetic
from fapake.ot import RSAKeyPair
from fapake.protocol import (
    DEMO_PARAMS,
    ClientSession,
    Params,
    ServerSession,
    hamming_distance,
    register_with_details,
    validate_password,
)
from fapake.rss import RobustSecretSharing

Scenario = Literal["honest", "corrupt-share", "cheating-server"]
SCENARIOS = ("honest", "corrupt-share", "cheating-server")

_key_cache: dict[int, RSAKeyPair] = {}


def ot_key_for(params: Params) -> RSAKeyPair:
    """One OT key per key size for the lifetime of the process (key generation is slow)."""
    bits = params.ot_key_bits
    if bits not in _key_cache:
        _key_cache[bits] = params.generate_ot_key()
    return _key_cache[bits]


def _s(value: int) -> str:
    return str(value)


def run_trace(
    registered: list[int],
    attempt: list[int],
    params: Params = DEMO_PARAMS,
    scenario: Scenario = "honest",
    target: int = 0,
    ot_key: RSAKeyPair | None = None,
) -> dict:
    """Register `registered`, log in with `attempt`, and return the full trace as a dict.

    scenario:
        honest           nothing unusual happens
        corrupt-share    the stored real share at index `target` is overwritten (disk damage)
        cheating-server  the server alters share `target` after encrypting, so OT and
                         ciphertext disagree
    """
    validate_password(registered, params.n)
    validate_password(attempt, params.n)
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}")
    if not 0 <= target < params.n:
        raise ValueError("target out of range")

    timings: dict[str, float] = {}
    clock = time.perf_counter()

    def lap(name: str) -> None:
        nonlocal clock
        now = time.perf_counter()
        timings[name] = round((now - clock) * 1000, 2)
        clock = now

    math = ModularArithmetic(params.group)
    key = ot_key or ot_key_for(params)
    lap("ot_key")

    # ------------------------------------------------------------------ registration
    record, secrets_ = register_with_details(registered, params)
    honest_stored = [list(pair) for pair in record.shares]
    if scenario == "corrupt-share":
        slot = registered[target]
        pair = list(record.shares[target])
        pair[slot] = math.modular_generator_exponentiation(math.generate_random_int(sub=True))
        record.shares[target] = tuple(pair)
    lap("register")

    # ------------------------------------------------------------------ server re-randomizes
    server = ServerSession(record, key, params)
    challenge = server.challenge()
    if scenario == "cheating-server":
        g = params.group.g
        a, b = server.shares[target]
        server.shares[target] = (math.modular_multiplication(a, g), math.modular_multiplication(b, g))
    lap("server")

    # ------------------------------------------------------------------ oblivious transfer
    client = ClientSession(attempt, params)
    offer = client.begin(challenge)
    rounds = []
    while not client.done:
        index, v = client.next_query(offer)
        x0, x1 = offer.x0, offer.x1
        reply = server.respond_ot(index, v)
        offer = client.receive(reply)
        if attempt[index] != registered[index]:
            kind = "decoy"
        elif scenario == "corrupt-share" and index == target:
            kind = "corrupted"
        elif scenario == "cheating-server" and index == target:
            kind = "altered"
        else:
            kind = "real"
        rounds.append(
            {
                "i": index,
                "bit": attempt[index],
                "x0": _s(x0),
                "x1": _s(x1),
                "v": _s(v),
                "c0": _s(reply.c0),
                "c1": _s(reply.c1),
                "received": _s(client.received[-1]),
                "kind": kind,
            }
        )
    lap("ot")

    # ------------------------------------------------------------------ reconstruction + checks
    result = client.finish()
    lap("finish")

    rss = RobustSecretSharing(params.n, params.t, params.e, math)
    votes = rss.votes(client.received)
    counts = Counter(vote.value for vote in votes)
    ranked = [value for value, _ in counts.most_common()]
    group_of = {value: i for i, value in enumerate(ranked)}
    top = counts[ranked[0]] if ranked else 0
    winner = 0 if ranked and list(counts.values()).count(top) == 1 else None
    small_group = params.group.p.bit_length() <= 64
    candidates = []
    for i, value in enumerate(ranked):
        shown = rss.unscale(value, params.n) if (small_group or i == winner) else None
        candidates.append({"value": None if shown is None else _s(shown), "count": counts[value]})
    lap("votes")

    return {
        "params": {
            "n": params.n,
            "t": params.t,
            "e": params.e,
            "group": {
                "name": params.group.name,
                "p": _s(params.group.p),
                "q": _s(params.group.q),
                "g": _s(params.group.g),
                "bits": params.group.p.bit_length(),
            },
            "ot_key_bits": key.N.bit_length(),
        },
        "registered": registered,
        "attempt": attempt,
        "distance": hamming_distance(registered, attempt),
        "scenario": {"kind": scenario, "target": target},
        "registration": {
            "k": _s(secrets_.k),
            "k_shares": [_s(x) for x in secrets_.k_shares],
            "decoy_exponents": [_s(x) for x in secrets_.decoy_exponents],
            "honest_stored": [[_s(a), _s(b)] for a, b in honest_stored],
            "stored": [[_s(a), _s(b)] for a, b in record.shares],
            "g_k": _s(record.k),
            "g_pw": _s(record.pw),
        },
        "server": {
            "r": _s(server.r),
            "r_shares": [_s(x) for x in server.r_shares],
            "masks": [_s(math.modular_generator_exponentiation(x)) for x in server.r_shares],
            "randomized": [[_s(a), _s(b)] for a, b in server.shares],
            "K": _s(server.randomized_key),
            "cipher": json.loads(challenge.cipher),
        },
        "ot": rounds,
        "reconstruction": {
            "votes": [{"xs": list(vote.xs), "candidate": group_of[vote.value]} for vote in votes],
            "candidates": candidates,
            "winner": winner,
            "subsets": len(votes),
        },
        "result": {
            "ok": result.ok,
            "reasons": result.reasons,
            "client_key": result.session_key,
            "server_key": server.session_key,
            "match": result.session_key == server.session_key,
        },
        "timings_ms": timings,
    }


def run_trace_json(options_json: str) -> str:
    """JSON in, JSON out. Entry point for the browser (Pyodide)."""
    options = json.loads(options_json)
    params = Params(group=GROUPS[options.get("group", "demo")])
    return json.dumps(
        run_trace(
            options["registered"],
            options["attempt"],
            params,
            options.get("scenario", "honest"),
            options.get("target", 0),
        )
    )


def main() -> None:
    args = sys.argv[1:]
    if len(args) != 2:
        print("usage: python -m fapake.trace REGISTERED_BITS ATTEMPT_BITS", file=sys.stderr)
        raise SystemExit(2)
    registered, attempt = ([int(c) for c in a] for a in args)
    print(json.dumps(run_trace(registered, attempt), indent=2))


if __name__ == "__main__":
    main()
