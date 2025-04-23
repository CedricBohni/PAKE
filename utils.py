def string_to_bitstring(s):
    return ''.join(format(ord(c), '08b') for c in s)
