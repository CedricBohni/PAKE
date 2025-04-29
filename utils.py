def string_to_bitstring(s: str) -> str:
    """
    Converts a string to its binary representation.

    Args:
        s (str): The input string.

    Returns:
        str: A string of binary digits representing the input string.
    """
    return ''.join(f'{ord(c):08b}' for c in s)
