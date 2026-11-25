import pytest

from fapake.modmath import ModularArithmetic
from fapake.rss import RobustSecretSharing

N, T, E = 8, 6, 1


@pytest.fixture
def rss():
    return RobustSecretSharing(N, T, E)


@pytest.fixture
def shared(rss):
    """(g^secret, exponentiated shares)."""
    math = rss.Math
    secret = math.generate_random_int(sub=True)
    shares = [math.modular_generator_exponentiation(s) for s in rss.generate_shares(secret)]
    return math.modular_generator_exponentiation(secret), shares


def test_reconstruct_all_shares(rss, shared):
    secret, shares = shared
    assert rss.reconstruct_secret(shares) == secret


def test_reconstruct_threshold_shares(rss, shared):
    secret, shares = shared
    assert rss.reconstruct_secret(shares[:T]) == secret


def test_too_few_shares(rss, shared):
    _, shares = shared
    assert rss.reconstruct_secret(shares[:T - 1]) is None


@pytest.mark.parametrize("bad_index", range(N))
def test_corrects_one_error(rss, shared, bad_index):
    secret, shares = shared
    shares[bad_index] = 1
    assert rss.reconstruct_secret(shares) == secret


def test_two_errors_not_recovered(rss, shared):
    secret, shares = shared
    shares[0] = shares[5] = 1
    assert rss.reconstruct_secret(shares) != secret


def test_rerandomization_is_homomorphic(rss, shared):
    """Multiplying in shares of a second secret gives shares of the product."""
    secret, shares = shared
    math = rss.Math
    r = math.generate_random_int(sub=True)
    masks = [math.modular_generator_exponentiation(s) for s in rss.generate_shares(r)]
    combined = [math.modular_multiplication(a, b) for a, b in zip(shares, masks)]
    expected = math.modular_multiplication(secret, math.modular_generator_exponentiation(r))
    assert rss.reconstruct_secret(combined) == expected


def test_custom_moduli_are_used():
    math = ModularArithmetic(generator=4, PRIME=47, sub_PRIME=23)
    assert math.sub_PRIME == 23
