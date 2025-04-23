from mpyc.runtime import mpc
import random

async def sender_ot(input1, input2):

    message = (None, None)
    choice = None

    for i in range(len(input1)):
        message = (input1[i], input2[i])

        async with mpc:
            secint = mpc.SecInt()
            x = mpc.input([secint(message[0]), secint(message[1])], 1)
            b = mpc.input(secint(choice), 2)
            a = await mpc.output(mpc.if_else(b, x[1], x[0]), 2)

async def receiver_ot(choices):
    message = (None, None)
    choice = None

    shares = []

    for i in range(len(choices)):
        choice = choices[i]

        async with mpc:
            secint = mpc.SecInt()
            x = mpc.input([secint(message[0]), secint(message[1])], 1)
            b = mpc.input(secint(choice), 2)
            a = await mpc.output(mpc.if_else(b, x[1], x[0]), 2)
            if a is not None:
                shares.append(a)

    return shares

async def helper_ot():
    message = (None, None)
    choice = None

    async with mpc:
        secint = mpc.SecInt()
        x = mpc.input([secint(message[0]), secint(message[1])], 1)
        b = mpc.input(secint(choice), 2)
        a = await mpc.output(mpc.if_else(b, x[1], x[0]), 2)

if __name__ == '__main__':
    while True:
        mpc.run(helper_ot())