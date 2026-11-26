import pytest

from fapake.modmath import DEMO_GROUP, MODP_2048, ModularArithmetic
from fapake.rss import RobustSecretSharing

N, T, E = 8, 6, 1


@pytest.fixture
def rss():
    return RobustSecretSharing(N, T, E, ModularArithmetic(DEMO_GROUP))


def share(rss):
    """(g^secret, exponentiated shares)."""
    math = rss.Math
    secret = math.generate_random_int(sub=True)
    shares = [math.modular_generator_exponentiation(s) for s in rss.generate_shares(secret)]
    return math.modular_generator_exponentiation(secret), shares


def test_reconstruct_all_shares(rss):
    secret, shares = share(rss)
    assert rss.reconstruct_secret(shares) == secret


def test_reconstruct_threshold_shares(rss):
    secret, shares = share(rss)
    assert rss.reconstruct_secret(shares[:T]) == secret


def test_too_few_shares(rss):
    _, shares = share(rss)
    assert rss.reconstruct_secret(shares[: T - 1]) is None


@pytest.mark.parametrize("bad_index", range(N))
def test_corrects_one_error(rss, bad_index):
    secret, shares = share(rss)
    shares[bad_index] = 1
    assert rss.reconstruct_secret(shares) == secret


def test_two_errors_not_recovered(rss):
    secret, shares = share(rss)
    shares[0] = shares[5] = 1
    assert rss.reconstruct_secret(shares) != secret


def test_rerandomization_is_homomorphic(rss):
    """Multiplying in shares of a second secret gives shares of the product."""
    secret, shares = share(rss)
    math = rss.Math
    r = math.generate_random_int(sub=True)
    masks = [math.modular_generator_exponentiation(s) for s in rss.generate_shares(r)]
    combined = [math.modular_multiplication(a, b) for a, b in zip(shares, masks)]
    expected = math.modular_multiplication(secret, math.modular_generator_exponentiation(r))
    assert rss.reconstruct_secret(combined) == expected


def test_fast_reconstruction_matches_textbook_lagrange(rss):
    """The integer-scaled interpolation gives the same result as λ_i computed mod q."""
    secret, shares = share(rss)
    math = rss.Math
    xs = list(range(1, T + 1))
    textbook = 1
    for i in range(T):
        textbook = math.modular_multiplication(
            textbook, math.modular_exponentiation(shares[i], rss.lagrange_coefficient(xs, i))
        )
    assert textbook == secret == rss.reconstruct_secret(shares[:T])


@pytest.mark.parametrize("bad_value", [0, DEMO_GROUP.p, -DEMO_GROUP.p])
def test_non_group_share_cannot_outvote_honest_ones(rss, bad_value):
    """0^c = 0 for every subset containing the bad share; it must not win the vote."""
    secret, shares = share(rss)
    shares[4] = bad_value
    assert rss.reconstruct_secret(shares) == secret


def test_invalid_shares_count_as_erasures(rss):
    """Shares that are visibly invalid are skipped; the remaining t honest ones suffice."""
    secret, shares = share(rss)
    shares[1] = shares[6] = 0
    assert rss.reconstruct_secret(shares) == secret
    shares[3] = 0
    assert rss.reconstruct_secret(shares) is None  # only t-1 usable shares left


@pytest.mark.slow
def test_secure_group_corrects_one_error():
    rss = RobustSecretSharing(N, T, E, ModularArithmetic(MODP_2048))
    secret, shares = share(rss)
    shares[3] = 2
    assert rss.reconstruct_secret(shares) == secret
