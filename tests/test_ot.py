import pytest

from fapake.ot import OTReceiver, OTSender, RSAKeyPair, key_bits_for


@pytest.mark.parametrize("choice", [0, 1])
def test_receiver_gets_chosen_message(demo_key, choice):
    sender = OTSender(demo_key)
    receiver = OTReceiver(demo_key.public)
    m0, m1 = 1111, 2222

    v = receiver.query(sender.offer, choice)
    reply = sender.respond(v, m0, m1)

    assert receiver.extract(reply.c0, reply.c1) == (m0, m1)[choice]


def test_other_message_stays_hidden(demo_key):
    sender = OTSender(demo_key)
    receiver = OTReceiver(demo_key.public)
    m0, m1 = 1111, 2222

    v = receiver.query(sender.offer, 0)
    k = receiver._k
    reply = sender.respond(v, m0, m1)

    # Unmasking the other ciphertext with the receiver's k gives garbage.
    assert (reply.c1 - k) % demo_key.N != m1


def test_offer_refreshes_each_round(demo_key):
    sender = OTSender(demo_key)
    first = sender.offer
    reply = sender.respond(OTReceiver(demo_key.public).query(first, 0), 1, 2)
    assert reply.next_offer == sender.offer != first


def test_random_values_span_the_modulus(demo_key):
    """OT randomness must be uniform mod N, not limited to a small range."""
    offers = [OTSender(demo_key).offer.x0 for _ in range(50)]
    assert max(offers).bit_length() > demo_key.N.bit_length() - 8


def test_messages_must_fit_in_modulus(demo_key):
    sender = OTSender(demo_key)
    with pytest.raises(ValueError):
        sender.respond(5, demo_key.N, 1)


def test_invalid_choice(demo_key):
    with pytest.raises(ValueError):
        OTReceiver(demo_key.public).query(OTSender(demo_key).offer, 2)


def test_private_values_not_in_repr(demo_key):
    text = repr(demo_key)
    assert str(demo_key.d) not in text and str(demo_key.prime1) not in text


def test_crt_matches_plain_exponentiation(demo_key):
    plain = RSAKeyPair(demo_key.N, demo_key.e, demo_key.d)
    for c in (0, 1, 2, 12345, demo_key.N - 1, 2**900 + 17):
        assert demo_key.private_power(c) == plain.private_power(c) == pow(c, demo_key.d, demo_key.N)


def test_ot_works_without_crt(demo_key):
    key = RSAKeyPair(demo_key.N, demo_key.e, demo_key.d)
    sender, receiver = OTSender(key), OTReceiver(key.public)
    reply = sender.respond(receiver.query(sender.offer, 1), 7, 8)
    assert receiver.extract(reply.c0, reply.c1) == 8


def test_inconsistent_primes_rejected(demo_key):
    with pytest.raises(ValueError):
        RSAKeyPair(demo_key.N, demo_key.e, demo_key.d, demo_key.prime1, 7)
    with pytest.raises(ValueError):
        RSAKeyPair(demo_key.N, demo_key.e, demo_key.d, demo_key.prime1)


@pytest.mark.parametrize("modulus_bits, expected", [(18, 1024), (1023, 1024), (1024, 2048), (2048, 3072)])
def test_key_bits_for(modulus_bits, expected):
    assert key_bits_for((1 << modulus_bits) - 1) == expected


def test_fresh_keys_differ(demo_key):
    from fapake.protocol import DEMO_PARAMS
    assert DEMO_PARAMS.generate_ot_key().N != demo_key.N
