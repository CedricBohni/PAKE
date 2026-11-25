import json

import pytest

from fapake.protocol import DEFAULT_PARAMS, DEMO_PARAMS
from fapake.trace import run_trace, run_trace_json

REG = [1, 0, 1, 0, 1, 0, 1, 0]


def flip(bits, *positions):
    out = bits[:]
    for i in positions:
        out[i] ^= 1
    return out


@pytest.fixture
def trace(demo_key):
    def run(attempt, scenario="honest", target=0, registered=REG):
        return run_trace(registered, attempt, DEMO_PARAMS, scenario, target, demo_key)
    return run


def test_exact_password(trace):
    t = trace(REG)
    assert t["distance"] == 0
    assert all(r["kind"] == "real" for r in t["ot"])
    assert t["result"]["ok"] and t["result"]["match"]
    rec = t["reconstruction"]
    assert rec["subsets"] == 28 and rec["winner"] == 0
    assert rec["candidates"] == [{"value": t["server"]["K"], "count": 28}]


def test_one_bit_off(trace):
    t = trace(flip(REG, 3))
    assert [r["kind"] for r in t["ot"]].count("decoy") == 1
    assert t["ot"][3]["kind"] == "decoy"
    assert t["result"]["match"]
    winner = t["reconstruction"]["candidates"][0]
    assert winner == {"value": t["server"]["K"], "count": 7}  # the 7 subsets without share 4


def test_two_bits_off(trace):
    t = trace(flip(REG, 0, 5))
    assert not t["result"]["match"]
    assert t["reconstruction"]["winner"] is None
    assert "reconstruction failed" in t["result"]["reasons"][0]


def test_stored_layout_follows_bits(trace):
    t = trace(REG)
    from fapake.modmath import DEMO_GROUP
    for bit, pair, share in zip(REG, t["registration"]["stored"], t["registration"]["k_shares"]):
        assert pair[bit] == str(pow(DEMO_GROUP.g, int(share), DEMO_GROUP.p))


def test_rerandomization_is_visible(trace):
    t = trace(REG)
    p = int(t["params"]["group"]["p"])
    for stored, mask, randomized in zip(t["registration"]["stored"], t["server"]["masks"],
                                        t["server"]["randomized"]):
        assert [int(s) * int(mask) % p for s in stored] == [int(x) for x in randomized]
    assert int(t["server"]["K"]) == int(t["registration"]["g_k"]) * pow(
        int(t["params"]["group"]["g"]), int(t["server"]["r"]), p) % p


def test_corrupted_share_is_corrected(trace):
    t = trace(REG, "corrupt-share", 2)
    assert t["ot"][2]["kind"] == "corrupted"
    assert t["registration"]["stored"][2] != t["registration"]["honest_stored"][2]
    assert t["result"]["match"]


def test_corruption_plus_wrong_bit_fails(trace):
    t = trace(flip(REG, 6), "corrupt-share", 2)
    assert not t["result"]["match"]


def test_cheating_server_is_caught(trace):
    t = trace(REG, "cheating-server", 4)
    assert t["ot"][4]["kind"] == "altered"
    assert not t["result"]["ok"]
    assert any("tampered" in r for r in t["result"]["reasons"])


def test_everything_is_json_safe(trace):
    t = trace(flip(REG, 1), "corrupt-share", 5)
    again = json.loads(json.dumps(t))
    assert again == t
    # big numbers travel as strings so JavaScript doesn't round them
    assert isinstance(t["server"]["K"], str) and isinstance(t["ot"][0]["v"], str)


def test_json_entry_point(demo_key):
    out = json.loads(run_trace_json(json.dumps({"registered": REG, "attempt": REG, "group": "demo"})))
    assert out["result"]["match"]


@pytest.mark.parametrize("bad", [
    {"scenario": "nope"},
    {"target": 8},
])
def test_rejects_bad_options(trace, bad):
    with pytest.raises(ValueError):
        trace(REG, **bad)


@pytest.mark.slow
def test_secure_group_trace(secure_key):
    t = run_trace(REG, flip(REG, 7), DEFAULT_PARAMS, ot_key=secure_key)
    assert t["params"]["group"]["bits"] == 2048
    assert t["result"]["match"]
    candidates = t["reconstruction"]["candidates"]
    assert candidates[0]["value"] == t["server"]["K"]
    assert all(c["value"] is None for c in candidates[1:])  # losers not unscaled in big groups
