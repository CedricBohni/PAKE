from mpyc.runtime import mpc
import random

# pid = 1
async def sender_ot(input):

    message = (None, None)
    choice = None

    for i in range(len(input)):
        message = (input[i][0], input[i][1])

        async with mpc:
            secint = mpc.SecInt(2048)
            x = mpc.input([secint(message[0]), secint(message[1])], 1)
            b = mpc.input(secint(choice), 2)
            a = await mpc.output(mpc.if_else(b, x[1], x[0]), 2)

# pid = 2
async def receiver_ot(choices):
    message = (None, None)
    choice = None

    shares = []

    for i in range(len(choices)):
        choice = choices[i]

        async with mpc:
            secint = mpc.SecInt(2048)
            x = mpc.input([secint(message[0]), secint(message[1])], 1)
            b = mpc.input(secint(choice), 2)
            a = await mpc.output(mpc.if_else(b, x[1], x[0]), 2)
            if a is not None:
                shares.append(a)

    return shares

# pid = 0
async def helper_ot():
    message = (None, None)
    choice = None

    async with mpc:
        secint = mpc.SecInt(2048)
        x = mpc.input([secint(message[0]), secint(message[1])], 1)
        b = mpc.input(secint(choice), 2)
        a = await mpc.output(mpc.if_else(b, x[1], x[0]), 2)

if __name__ == '__main__':
    while True:
        mpc.run(helper_ot())