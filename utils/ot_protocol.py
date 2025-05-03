from mpyc.runtime import mpc

# pid = 1
async def sender_ot(input):
    """
    Implements a three-party OT (Oblivious Transfer) protocol using the mpyc library.

    This protocol simulates the functionality of a two-party OT protocol, requiring all three parties'
    code to run in the same file with a matching structure.

    Args:
        input (list[tuple[int, int]]): A list of tuples, where each tuple contains two messages
                                       (message0, message1) to send.

    Functionality:
        - Securely inputs the two messages and the receiver's choice.
        - Outputs the selected message based on the receiver's choice.
    """

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
async def receiver_ot(choices_bits):
    """
    Implements a three-party OT (Oblivious Transfer) protocol using the mpyc library.
    This represents the functionality of two-party OT protocol and requires all three parties' code
    to run in the same file with a matching structure.

    Args:
        choices_bits: A list of receiver's choices (0 or 1) for each OT instance.

    Returns:
        A list of selected messages based on the receiver's choices.

    Functionality:
        - Securely inputs the two messages and the receiver's choice.
        - Outputs the selected message for each choice in the list.
    """

    message = (None, None)
    choice = None

    shares = []

    for i in range(len(choices_bits)):
        choice = choices_bits[i]

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
    """
        Implements the helper functionality for a three-party OT (Oblivious Transfer) protocol using the mpyc library.

        This function acts as a helper in the OT protocol, facilitating secure computation between the sender and receiver.

        Functionality:
            - Securely inputs two messages and the receiver's choice.
            - Outputs the selected message based on the receiver's choice.

        Note:
            This function is designed to be run as part of the mpyc runtime.
    """

    message = (None, None)
    choice = None

    async with mpc:
        secint = mpc.SecInt(2048)
        x = mpc.input([secint(message[0]), secint(message[1])], 1)
        b = mpc.input(secint(choice), 2)
        a = await mpc.output(mpc.if_else(b, x[1], x[0]), 2)

def start_ot_helper():
    while True:
        mpc.run(helper_ot())