import pytest
from sympy import isprime

from fapake.modmath import DEFAULT_GROUP, DEMO_GROUP, GROUPS, MODP_2048, Group, ModularArithmetic


def test_default_group_is_the_secure_one():
    assert DEFAULT_GROUP is MODP_2048
    assert MODP_2048.p.bit_length() == 2048


@pytest.mark.parametrize("group", GROUPS.values(), ids=GROUPS.keys())
def test_groups_are_safe_prime_subgroups(group):
    assert isprime(group.p) and isprime(group.q)
    assert group.p == 2 * group.q + 1
    assert pow(group.g, group.q, group.p) == 1


@pytest.mark.parametrize("p, q, g", [(47, 22, 4), (47, 23, 1), (47, 23, 5)])
def test_invalid_groups_rejected(p, q, g):
    with pytest.raises(ValueError):
        Group("bad", p, q, g)


def test_uses_the_given_group():
    math = ModularArithmetic(DEMO_GROUP)
    assert (math.PRIME, math.sub_PRIME, math.generator) == (DEMO_GROUP.p, DEMO_GROUP.q, DEMO_GROUP.g)


@pytest.mark.parametrize("sub", [True, False])
def test_random_ints_in_range(sub):
    math = ModularArithmetic(DEMO_GROUP)
    limit = DEMO_GROUP.q if sub else DEMO_GROUP.p
    values = {math.generate_random_int(sub) for _ in range(2000)}
    assert all(1 <= v < limit for v in values)
    assert len(values) > 1900  # not stuck on a few values


def test_inverse_and_division():
    math = ModularArithmetic(DEMO_GROUP)
    a = 12345
    assert math.modular_multiplication(a, math.modular_inverse(a, sub=True), sub=True) == 1
    assert math.modular_multiplication(math.modular_division(7, a), a) == 7
