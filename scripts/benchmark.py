"""Time registration and login for several parameter sets.

    uv run python scripts/benchmark.py            # writes docs/benchmark.json and docs/benchmark.md

Each login is split into three phases:
    server  ServerSession: re-randomize the record, encrypt, prepare OT
    ot      the n oblivious transfers (2 RSA private-key operations each)
    finish  robust reconstruction over all C(n, t) subsets, decryption, checks
Times are medians over --repeats logins with a one-bit-wrong password.
"""

import argparse
import json
import platform
import statistics
import time
from math import comb
from pathlib import Path

from fapake.modmath import DEMO_GROUP, MODP_2048
from fapake.protocol import ClientSession, Params, ServerSession, register, run_ot_rounds

DOCS = Path(__file__).resolve().parent.parent / "docs"

CONFIGS = [
    # (group, n, t, e)
    (MODP_2048, 8, 6, 1),
    (MODP_2048, 10, 6, 2),
    (MODP_2048, 12, 8, 2),
    (MODP_2048, 12, 6, 3),
    (MODP_2048, 16, 12, 2),
    (DEMO_GROUP, 8, 6, 1),
]


def timed(fn, *args):
    start = time.perf_counter()
    result = fn(*args)
    return result, (time.perf_counter() - start) * 1000


def run_config(group, n, t, e, repeats):
    params = Params(n=n, t=t, e=e, group=group)
    key = params.generate_ot_key()
    password = [i % 2 for i in range(n)]
    attempt = password[:]
    attempt[-1] ^= 1

    record, register_ms = timed(register, password, params)
    phases = {"server": [], "ot": [], "finish": []}
    for _ in range(repeats):
        server, ms = timed(ServerSession, record, key, params)
        phases["server"].append(ms)
        client = ClientSession(attempt, params)
        _, ms = timed(run_ot_rounds, server, client)
        phases["ot"].append(ms)
        result, ms = timed(client.finish)
        phases["finish"].append(ms)
        if result.session_key != server.session_key:
            raise RuntimeError(f"login failed for n={n}, t={t}, e={e}")

    medians = {name: round(statistics.median(values), 1) for name, values in phases.items()}
    return {
        "group": group.name,
        "group_bits": group.p.bit_length(),
        "ot_key_bits": key.N.bit_length(),
        "n": n,
        "t": t,
        "e": e,
        "subsets": comb(n, t),
        "register_ms": round(register_ms, 1),
        **{f"{name}_ms": value for name, value in medians.items()},
        "login_ms": round(sum(medians.values()), 1),
    }


def ms(value: float) -> str:
    return "<1" if value < 1 else f"{value:,.0f}"


def to_markdown(rows, meta):
    lines = [
        "| Group | n | t | e | Subsets C(n,t) | Register (ms) | Server (ms) | OT (ms) | Reconstruct + checks (ms) "
        "| Login total (ms) |",
        "|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|",
    ]
    for r in rows:
        group = "2048-bit" if r["group"] == "modp2048" else "demo 18-bit"
        lines.append(
            f"| {group} | {r['n']} | {r['t']} | {r['e']} | {r['subsets']:,} | {ms(r['register_ms'])} "
            f"| {ms(r['server_ms'])} | {ms(r['ot_ms'])} | {ms(r['finish_ms'])} | **{ms(r['login_ms'])}** |"
        )
    lines.append("")
    lines.append(f"Median of {meta['repeats']} logins with one wrong bit. {meta['machine']}, Python {meta['python']}.")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()

    rows = []
    for group, n, t, e in CONFIGS:
        print(f"{group.name:9} n={n:2} t={t:2} e={e} ...", end=" ", flush=True)
        row = run_config(group, n, t, e, args.repeats)
        print(f"login {row['login_ms']:.0f} ms")
        rows.append(row)

    meta = {
        "repeats": args.repeats,
        "python": platform.python_version(),
        "machine": f"{platform.system()} {platform.machine()}",
    }
    DOCS.mkdir(exist_ok=True)
    (DOCS / "benchmark.json").write_text(json.dumps({"meta": meta, "rows": rows}, indent=2) + "\n")
    (DOCS / "benchmark.md").write_text(to_markdown(rows, meta))
    print(f"wrote {DOCS / 'benchmark.json'} and {DOCS / 'benchmark.md'}")


if __name__ == "__main__":
    main()
