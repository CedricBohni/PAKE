# faPAKE

This repository implements the **fuzzy aPAKE** protocol, as described in the paper *"Fuzzy Password-Authenticated Key Exchange"* by Erwig, A. H. The protocol enables secure password-authenticated key exchange (PAKE) using fuzzy matching techniques.

## Features

- **Robust Secret Sharing**: Implements a robust secret sharing scheme to handle password-based authentication.
- **Fuzzy Matching**: Supports authentication even with slight variations in the password using Hamming distance.
- **Oblivious Transfer Protocol**: Ensures secure exchange of password shares between the client and server.
- **Session Key Generation**: Generates a secure session key upon successful authentication.

## How to run

### 1. Install uv

The project uses [uv](https://docs.astral.sh/uv/) to manage Python and its dependencies. If Python 3.11 or newer isn't installed, uv downloads it automatically.

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

macOS / Linux:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Open a new terminal afterwards so the `uv` command is found.

### 2. Get the code and install dependencies

```bash
git clone https://github.com/CedricBohni/PAKE.git
cd PAKE
uv sync
```

`uv sync` creates a `.venv` folder inside the project and installs `cryptography` and `sympy` there. Nothing is installed globally.

### 3. Start the server

```bash
uv run fapake-server
```

It prints `Server listening on 127.0.0.1:65432` and keeps running. Stop it with `Ctrl+C`.

### 4. Start the client

In a **second terminal**, from the same folder:

```bash
uv run fapake-client
```

### 5. Try it

1. Choose `1` to register. Enter a username and an 8-bit password such as `10101010`.
2. Choose `2` to authenticate with the same username and password. The client prints a `SESSION KEY`, and the server prints the same key in its terminal.
3. Authenticate again with one bit changed, such as `10101011`. The keys still match: this is the fuzzy part.
4. Authenticate with two bits changed, such as `10101111`. The client prints a reason and a different key, so authentication failed.

See the [example session](#example-registration) below.

### Options

| Command | Option | Default | Meaning |
| --- | --- | --- | --- |
| both | `--host` | `127.0.0.1` | Address to listen on / connect to |
| both | `--port` | `65432` | TCP port (use the same on both sides) |
| `fapake-server` | `--store` | `userFiles` | Folder where user records are saved |

If the port is already in use, pick another one on both sides, for example `uv run fapake-server --port 65500` and `uv run fapake-client --port 65500`.

### Without uv

With Python 3.11+ and pip:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e .
fapake-server        # and in a second terminal: fapake-client
```

### Troubleshooting

- **`invalid peer certificate: UnknownIssuer` during `uv sync`**: antivirus software or a company proxy is intercepting HTTPS. Run `uv sync --system-certs`, or set the environment variable `UV_SYSTEM_CERTS=1` permanently.
- **`cannot reach server`**: the server isn't running, or the client uses a different `--port`.

## Tests

```bash
uv run pytest
```

The tests cover secret sharing, oblivious transfer, the full protocol (exact, 1-bit-off and 2-bit-off passwords, corrupted records, an inconsistent server), and a real TCP round trip.

## Project layout

| Path | Contents |
| --- | --- |
| `src/fapake/protocol.py` | The protocol itself: registration, server and client sessions, no networking |
| `src/fapake/rss.py` | Robust secret sharing in the exponent |
| `src/fapake/ot.py` | RSA-based 1-out-of-2 oblivious transfer |
| `src/fapake/ic.py` | AES-GCM encryption keyed by a group element |
| `src/fapake/modmath.py` | Modular arithmetic and group parameters |
| `src/fapake/server.py`, `client.py` | TCP server and interactive client |
| `development/` | Earlier experiments (Berlekamp-Welch decoding, brute force) |

## Security note

This is a research demo. The group parameters are tiny, the oblivious-transfer RSA key is fixed and public, and randomness comes from Python's `random` module. Do not use it to protect anything.

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