from mpyc.runtime import mpc
import random

async def sender_ot(input):

    message = (None, None)
    choice = None

    for i in range(len(input)):
        message = (input[i][0], input[i][1])

        print(f"Sender message: {message}")

        async with mpc:
            secint = mpc.SecInt(2048)
            x = mpc.input([secint(message[0]), secint(message[1])], 1)
            b = mpc.input(secint(choice), 2)
            a = await mpc.output(mpc.if_else(b, x[1], x[0]), 2)

async def receiver_ot(choices):
    message = (None, None)
    choice = None

    shares = []

    for i in range(len(choices)):
        choice = choices[i]

        print(f"Receiver choice: {choice}")

        async with mpc:
            secint = mpc.SecInt(2048)
            x = mpc.input([secint(message[0]), secint(message[1])], 1)
            b = mpc.input(secint(choice), 2)
            a = await mpc.output(mpc.if_else(b, x[1], x[0]), 2)
            if a is not None:
                shares.append(a)
                print(f"Receiver message: {a}")

    return shares

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