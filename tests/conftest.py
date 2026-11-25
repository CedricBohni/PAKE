import pytest

from fapake.protocol import DEFAULT_PARAMS, DEMO_PARAMS


@pytest.fixture(scope="session")
def demo_key():
    """1024-bit OT key, enough for the demo group and quick to generate."""
    return DEMO_PARAMS.generate_ot_key()


@pytest.fixture(scope="session")
def secure_key():
    """3072-bit OT key for the 2048-bit group. Generated once per test run."""
    return DEFAULT_PARAMS.generate_ot_key()
