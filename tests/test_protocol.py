import pytest

from fapake.ot import generate_key
from fapake.protocol import (DEFAULT_PARAMS, DEMO_PARAMS, ClientSession, Params, ProtocolError,
                             ServerSession, UserRecord, authenticate_locally, hamming_distance,
                             parse_password, passwords_within_distance, register, run_ot_rounds)

PASSWORD = [1, 0, 1, 0, 1, 0, 1, 0]


def flip(password, *positions):
    result = password[:]
    for i in positions:
        result[i] ^= 1
    return result


@pytest.fixture
def record():
    return register(PASSWORD, DEMO_PARAMS)


@pytest.fixture
def auth(demo_key):
    """authenticate_locally on the demo group with the shared test key."""
    def run(record, password, params=DEMO_PARAMS):
        return authenticate_locally(record, password, params, demo_key)
    return run


def test_correct_password_agrees_on_key(record, auth):
    server, result = auth(record, PASSWORD)
    assert result.ok, result.reasons
    assert result.session_key == server.session_key
    assert len(bytes.fromhex(result.session_key)) == 32


@pytest.mark.parametrize("position", range(8))
def test_one_bit_off_still_agrees(record, auth, position):
    server, result = auth(record, flip(PASSWORD, position))
    assert result.ok, result.reasons
    assert result.session_key == server.session_key


@pytest.mark.parametrize("positions", [(0, 1), (2, 7), (3, 4)])
def test_two_bits_off_fails(record, auth, positions):
    server, result = auth(record, flip(PASSWORD, *positions))
    assert not result.ok
    assert result.session_key != server.session_key


def test_completely_wrong_password_fails(record, auth):
    server, result = auth(record, flip(PASSWORD, *range(8)))
    assert not result.ok
    assert result.session_key != server.session_key


def test_failed_keys_are_random(record, auth):
    _, first = auth(record, flip(PASSWORD, 0, 1))
    _, second = auth(record, flip(PASSWORD, 0, 1))
    assert first.session_key != second.session_key


def test_sessions_use_fresh_keys(record, auth):
    first, _ = auth(record, PASSWORD)
    second, _ = auth(record, PASSWORD)
    assert first.session_key != second.session_key


def test_record_does_not_contain_password(record):
    data = record.to_dict()
    assert set(data) == {"group", "shares", "pw", "k"}
    assert data["group"] == "demo"
    assert UserRecord.from_dict(data) == record


def test_old_records_without_group_load_as_demo(record):
    data = record.to_dict()
    del data["group"]
    assert UserRecord.from_dict(data).group == "demo"


def test_one_corrupted_stored_share_is_corrected(record, auth):
    zero, one = record.shares[3]
    record.shares[3] = (zero, 12345) if PASSWORD[3] == 1 else (12345, one)
    server, result = auth(record, PASSWORD)
    assert result.ok, result.reasons
    assert result.session_key == server.session_key


def test_inconsistent_server_is_detected(record, demo_key):
    """A server sending a different share over OT than in the ciphertext is caught,
    even though robust reconstruction alone would have corrected it."""
    server = ServerSession(record, demo_key, DEMO_PARAMS)
    client = ClientSession(PASSWORD, DEMO_PARAMS)
    server.shares[2] = (server.shares[2][0] + 1, server.shares[2][1] + 1)

    run_ot_rounds(server, client)
    result = client.finish()

    assert not result.ok
    assert any("tampered" in reason for reason in result.reasons)


def test_server_limits_ot_requests(record, demo_key):
    server = ServerSession(record, demo_key, DEMO_PARAMS)
    run_ot_rounds(server, ClientSession(PASSWORD, DEMO_PARAMS))
    with pytest.raises(ProtocolError, match="Too many requests"):
        server.respond_ot(0, 1)


@pytest.mark.parametrize("index, v", [(8, 1), (-1, 1), ("0", 1), (True, 1), (0, "1"), (0, None)])
def test_server_rejects_bad_ot_requests(record, demo_key, index, v):
    with pytest.raises(ProtocolError):
        ServerSession(record, demo_key, DEMO_PARAMS).respond_ot(index, v)


def test_client_cannot_finish_early(record, demo_key):
    client = ClientSession(PASSWORD, DEMO_PARAMS)
    client.begin(ServerSession(record, demo_key, DEMO_PARAMS).challenge())
    with pytest.raises(ProtocolError):
        client.finish()


def test_client_needs_challenge_first(record, demo_key):
    offer = ServerSession(record, demo_key, DEMO_PARAMS).challenge().offer
    with pytest.raises(ProtocolError):
        ClientSession(PASSWORD, DEMO_PARAMS).next_query(offer)


def test_server_rejects_record_from_other_group(record, secure_key):
    with pytest.raises(ProtocolError, match="registered with group 'demo'"):
        ServerSession(record, secure_key, DEFAULT_PARAMS)


def test_client_rejects_challenge_from_other_group(record, demo_key):
    challenge = ServerSession(record, demo_key, DEMO_PARAMS).challenge()
    with pytest.raises(ProtocolError, match="server uses group 'demo'"):
        ClientSession(PASSWORD, DEFAULT_PARAMS).begin(challenge)


def test_ot_key_must_exceed_group_prime(demo_key):
    record = register(PASSWORD, DEFAULT_PARAMS)
    with pytest.raises(ValueError, match="larger than the group prime"):
        ServerSession(record, demo_key, DEFAULT_PARAMS)


@pytest.mark.parametrize("text", ["1010101", "101010101", "1010102a", ""])
def test_parse_password_rejects(text):
    with pytest.raises(ProtocolError):
        parse_password(text)


def test_parse_password():
    assert parse_password(" 10101010\n") == PASSWORD


@pytest.mark.parametrize("bad", [[1, 0], [2] * 8, [True] * 8, "10101010", None])
def test_register_rejects_bad_password(bad):
    with pytest.raises(ProtocolError):
        register(bad, DEMO_PARAMS)


@pytest.mark.parametrize("distance, expected", [(0, 1), (1, 9), (2, 37)])
def test_passwords_within_distance(distance, expected):
    neighbours = passwords_within_distance(PASSWORD, distance)
    assert len(neighbours) == expected
    assert neighbours[0] == PASSWORD
    assert all(hamming_distance(PASSWORD, pw) <= distance for pw in neighbours)


def test_params_validation():
    with pytest.raises(ValueError):
        Params(n=8, t=6, e=2)
    with pytest.raises(ValueError):
        Params(n=8, t=9, e=0)


def test_larger_tolerance(auth):
    """With n=10, t=6, e=2 two wrong bits are tolerated but three are not."""
    params = Params(n=10, t=6, e=2, group=DEMO_PARAMS.group)
    password = [1, 1, 0, 0, 1, 0, 1, 0, 0, 1]
    record = register(password, params)

    server, result = auth(record, flip(password, 1, 8), params)
    assert result.ok, result.reasons
    assert result.session_key == server.session_key

    server, result = auth(record, flip(password, 0, 4, 9), params)
    assert result.session_key != server.session_key


# ----------------------------------------------------------------- the real 2048-bit group

@pytest.fixture(scope="module")
def secure_record():
    return register(PASSWORD, DEFAULT_PARAMS)


@pytest.mark.slow
@pytest.mark.parametrize("password, should_match", [
    (PASSWORD, True),
    (flip(PASSWORD, 5), True),
    (flip(PASSWORD, 0, 6), False),
], ids=["exact", "one-bit-off", "two-bits-off"])
def test_secure_group(secure_record, secure_key, password, should_match):
    assert secure_key.N.bit_length() == 3072
    server, result = authenticate_locally(secure_record, password, DEFAULT_PARAMS, secure_key)
    assert result.ok is should_match, result.reasons
    assert (result.session_key == server.session_key) is should_match


def test_authenticate_locally_generates_key_when_missing(record):
    server, result = authenticate_locally(record, PASSWORD, DEMO_PARAMS)
    assert result.session_key == server.session_key
