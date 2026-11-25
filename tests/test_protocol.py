import pytest

from fapake.protocol import (ClientSession, Params, ProtocolError, ServerSession, UserRecord,
                             authenticate_locally, hamming_distance, parse_password,
                             passwords_within_distance, register)

PASSWORD = [1, 0, 1, 0, 1, 0, 1, 0]


def flip(password, *positions):
    result = password[:]
    for i in positions:
        result[i] ^= 1
    return result


@pytest.fixture
def record():
    return register(PASSWORD)


def test_correct_password_agrees_on_key(record):
    server, result = authenticate_locally(record, PASSWORD)
    assert result.ok, result.reasons
    assert result.session_key == server.session_key


@pytest.mark.parametrize("position", range(8))
def test_one_bit_off_still_agrees(record, position):
    server, result = authenticate_locally(record, flip(PASSWORD, position))
    assert result.ok, result.reasons
    assert result.session_key == server.session_key


@pytest.mark.parametrize("positions", [(0, 1), (2, 7), (3, 4)])
def test_two_bits_off_fails(record, positions):
    server, result = authenticate_locally(record, flip(PASSWORD, *positions))
    assert not result.ok
    assert result.session_key != server.session_key


def test_completely_wrong_password_fails(record):
    server, result = authenticate_locally(record, flip(PASSWORD, *range(8)))
    assert not result.ok
    assert result.session_key != server.session_key


def test_sessions_use_fresh_keys(record):
    first, _ = authenticate_locally(record, PASSWORD)
    second, _ = authenticate_locally(record, PASSWORD)
    assert first.session_key != second.session_key


def test_record_does_not_contain_password(record):
    data = record.to_dict()
    assert set(data) == {"shares", "pw", "k"}
    assert UserRecord.from_dict(data) == record


def test_one_corrupted_stored_share_is_corrected(record):
    zero, one = record.shares[3]
    record.shares[3] = (zero, 12345) if PASSWORD[3] == 1 else (12345, one)
    server, result = authenticate_locally(record, PASSWORD)
    assert result.ok, result.reasons
    assert result.session_key == server.session_key


def test_inconsistent_server_is_detected(record):
    """A server sending a different share over OT than in the ciphertext is caught,
    even though robust reconstruction alone would have corrected it."""
    server = ServerSession(record)
    client = ClientSession(PASSWORD)
    challenge = server.challenge()
    server.shares[2] = (server.shares[2][0] + 1, server.shares[2][1] + 1)

    offer = challenge.offer
    while not client.done:
        index, v = client.next_query(offer)
        offer = client.receive(server.respond_ot(index, v))
    result = client.finish(challenge.cipher)

    assert not result.ok
    assert any("tampered" in reason for reason in result.reasons)


def test_server_limits_ot_requests(record):
    server = ServerSession(record)
    client = ClientSession(PASSWORD)
    offer = server.challenge().offer
    for _ in range(8):
        index, v = client.next_query(offer)
        offer = client.receive(server.respond_ot(index, v))
    with pytest.raises(ProtocolError, match="Too many requests"):
        server.respond_ot(0, 1)


def test_server_rejects_bad_index(record):
    with pytest.raises(ProtocolError):
        ServerSession(record).respond_ot(8, 1)


def test_client_cannot_finish_early(record):
    with pytest.raises(ProtocolError):
        ClientSession(PASSWORD).finish(ServerSession(record).challenge().cipher)


@pytest.mark.parametrize("text", ["1010101", "101010101", "1010102a", ""])
def test_parse_password_rejects(text):
    with pytest.raises(ProtocolError):
        parse_password(text)


def test_parse_password():
    assert parse_password(" 10101010\n") == PASSWORD


@pytest.mark.parametrize("bad", [[1, 0], [2] * 8, [True] * 8, "10101010", None])
def test_register_rejects_bad_password(bad):
    with pytest.raises(ProtocolError):
        register(bad)


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


def test_larger_tolerance():
    """With n=10, t=6, e=2 two wrong bits are tolerated but three are not."""
    params = Params(n=10, t=6, e=2)
    password = [1, 1, 0, 0, 1, 0, 1, 0, 0, 1]
    record = register(password, params)
    server, result = authenticate_locally(record, flip(password, 1, 8), params)
    assert result.ok, result.reasons
    assert result.session_key == server.session_key

    server, result = authenticate_locally(record, flip(password, 0, 4, 9), params)
    assert result.session_key != server.session_key
