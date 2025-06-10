# faPAKE

This repository implements the **fuzzy aPAKE** protocol, as described in the paper *"Fuzzy Password-Authenticated Key Exchange"* by Erwig, A. H. The protocol enables secure password-authenticated key exchange (PAKE) using fuzzy matching techniques.

## Features

- **Robust Secret Sharing**: Implements a robust secret sharing scheme to handle password-based authentication.
- **Fuzzy Matching**: Supports authentication even with slight variations in the password using Hamming distance.
- **Oblivious Transfer Protocol**: Ensures secure exchange of password shares between the client and server.
- **Session Key Generation**: Generates a secure session key upon successful authentication.

## Requirements

- Python 3.8 or higher
- Required Python libraries:
  - `socket`
  - `json`
  - `time`

## Usage
1. Start the server by running `python server.py`.
2. Start the client by running `python client.py`.
3. Follow the prompts in the client to enter your password and authenticate.
4. If the authentication is successful, a secure session key will be generated and displayed.
5. To test the fuzzy matching, you can enter a password that is similar to the one registered on the server (e.g., with a small typo or variation).

## Example Registration
```plaintext
Choose an action:
1. Register
2. Authenticate
any: Exit
Enter your choice: 1
=== User Registration ===
Enter username: alice
Enter 8-bit password: 10101010
Server registration response: Registration successful
Time taken for registration: 0.123456 seconds
```
## Example Authentication
```plaintext
Choose an action:
1. Register
2. Authenticate
any: Exit
Enter your choice: 2
=== User Authentication ===
Enter username: alice
Enter 8-bit password: 10101011
SESSION KEY: 123456789abcdef
Time taken for authentication: 0.123456 seconds
```