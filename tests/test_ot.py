import random

import pytest

from fapake.ot import DEMO_KEY, OTReceiver, OTSender


def rand():
    return random.randint(1, 2**64)


@pytest.mark.parametrize("choice", [0, 1])
def test_receiver_gets_chosen_message(choice):
    sender = OTSender(DEMO_KEY, rand)
    receiver = OTReceiver(DEMO_KEY.public, rand)
    m0, m1 = 1111, 2222

    v = receiver.query(sender.offer, choice)
    reply = sender.respond(v, m0, m1)

    assert receiver.extract(reply.c0, reply.c1) == (m0, m1)[choice]


def test_other_message_stays_hidden():
    sender = OTSender(DEMO_KEY, rand)
    receiver = OTReceiver(DEMO_KEY.public, rand)
    m0, m1 = 1111, 2222

    v = receiver.query(sender.offer, 0)
    k = receiver._k
    reply = sender.respond(v, m0, m1)

    # Unmasking the other ciphertext with the receiver's k gives garbage.
    assert (reply.c1 - k) % DEMO_KEY.N != m1


def test_offer_refreshes_each_round():
    sender = OTSender(DEMO_KEY, rand)
    first = sender.offer
    reply = sender.respond(OTReceiver(DEMO_KEY.public, rand).query(first, 0), 1, 2)
    assert reply.next_offer == sender.offer != first


def test_invalid_choice():
    with pytest.raises(ValueError):
        OTReceiver(DEMO_KEY.public, rand).query(OTSender(DEMO_KEY, rand).offer, 2)
