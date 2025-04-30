# faPAKE
This code implements the faPAKE protocol as described in the paper "faPAKE: fuzzy password-authenticated key exchange" by J. Liu, Y. Zhang, and H. Wang.
The protocol is designed to provide secure password-authenticated key exchange (PAKE) using fuzzy matching techniques.
# Protocol Structure
The protocol consists of two main phases:
1. **Password Registration**: In this phase, the user registers their password with the server. The server stores a fuzzy representation of the password.
2. **Key Exchange**: In this phase, the user and server perform a key exchange using the registered password. The user can authenticate to the server using a password that is similar to the registered password, allowing for fuzzy matching.
3. **Explicit Authentication**: The user can explicitly authenticate to the server using a password that is not similar to the registered password. This allows for a more secure authentication process.

# Implementation
## Password Registration

## Key Exchange

## Explicit Authentication


TODOs
- connect RSS
- all in exponent
- randomize

run these three at the same time:
- `python server.py -M 3 -I 1`
- `python client.py -M 3 -I 2`
- `python ot_helper.py -M 3 -I 0`