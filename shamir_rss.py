import random

def shamir_share(secret, n, t, p):
    coeffs = [secret] + [random.randint(0, p - 1) for _ in range(t)]
    shares = []
    for i in range(1, n + 1):
        x = i
        y = sum([coeffs[j] * (x ** j) for j in range(len(coeffs))]) % p
        shares.append((x, y))
    return shares