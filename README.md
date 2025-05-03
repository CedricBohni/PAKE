# faPAKE

This repository implements the **faPAKE** protocol, as described in the paper *"faPAKE: Fuzzy Password-Authenticated Key Exchange"* by J. Liu, Y. Zhang, and H. Wang. The protocol enables secure password-authenticated key exchange (PAKE) using fuzzy matching techniques.


## TODOs

- Implement RSS without brute force.
- Move all computations to the exponent for improved secrecy.

run these three at the same time:
- `python server.py -M 3 -I 1`
- `python client.py -M 3 -I 2`
- `python ot_helper.py -M 3 -I 0`