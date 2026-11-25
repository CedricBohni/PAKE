# faPAKE

This repository implements the **fuzzy aPAKE** protocol, as described in the paper *"Fuzzy Password-Authenticated Key Exchange"* by Erwig, A. H. The protocol enables secure password-authenticated key exchange (PAKE) using fuzzy matching techniques.

## Features

- **Robust Secret Sharing**: Implements a robust secret sharing scheme to handle password-based authentication.
- **Fuzzy Matching**: Supports authentication even with slight variations in the password using Hamming distance.
- **Oblivious Transfer Protocol**: Ensures secure exchange of password shares between the client and server.
- **Session Key Generation**: Generates a secure session key upon successful authentication.

## Interactive visualizer

`web/` contains a step-by-step walkthrough of one login: registration, the per-login mask, the eight oblivious transfers, the 28-subset majority vote and the final checks. Flip password bits, simulate a damaged record or a cheating server, and switch between the readable demo group and the real 2048-bit group. Every number shown is computed by this package's Python code, running in the browser via [Pyodide](https://pyodide.org).

Run it locally:

```bash
uv run python web/serve.py
```

Then open <http://localhost:8000>. The first load downloads the Python runtime (about 10 seconds); after that each change recomputes in a fraction of a second in the demo group.

The `visualizer` workflow publishes it to GitHub Pages on every push to `master`. To turn that on, set the repository's **Settings → Pages → Source** to **GitHub Actions**. The page is then served at `https://<user>.github.io/PAKE/`.

The same trace is available from the command line as JSON:

```bash
uv run python -m fapake.trace 10101010 10101011
```

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

`uv sync` creates a `.venv` folder inside the project and installs `cryptography` there (plus `pytest` and `sympy` for the tests). Nothing is installed globally.

### 3. Start the server

```bash
uv run fapake-server
```

It first generates a fresh RSA key for the oblivious transfer (about a second), then prints `Server listening on 127.0.0.1:65432 (group modp2048, OT key 3072 bits)` and keeps running. Stop it with `Ctrl+C`.

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

See the [example session](#example-registration) below. An authentication takes under a second with the default 2048-bit group.

### Demo mode

To see the numbers the protocol works with, start **both** sides with `--demo`:

```bash
uv run fapake-server --demo
uv run fapake-client --demo
```

This switches to an 18-bit toy group (and a 1024-bit OT key). Everything is fast and the values in `userFiles/` are short enough to read, but it offers no security. If only one side uses `--demo`, the client reports the mismatch.

### Options

| Command | Option | Default | Meaning |
| --- | --- | --- | --- |
| both | `--host` | `127.0.0.1` | Address to listen on / connect to |
| both | `--port` | `65432` | TCP port (use the same on both sides) |
| both | `--demo` | off | Use the insecure toy group (must match on both sides) |
| `fapake-server` | `--store` | `userFiles` | Folder where user records are saved |

Users registered in one mode can't log in while the server runs in the other mode. Each record stores which group it was made with.

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

The tests cover the group parameters, secret sharing, oblivious transfer, message framing, the full protocol (exact, 1-bit-off and 2-bit-off passwords, corrupted records, an inconsistent server, mismatched groups), and real TCP sessions, including several clients at once. Most tests use the demo group. The ones marked `slow` use the real 2048-bit group; skip them with `uv run pytest -m "not slow"`.

## Project layout

| Path | Contents |
| --- | --- |
| `src/fapake/protocol.py` | The protocol itself: registration, server and client sessions, no networking |
| `src/fapake/rss.py` | Robust secret sharing in the exponent |
| `src/fapake/ot.py` | RSA-based 1-out-of-2 oblivious transfer |
| `src/fapake/ic.py` | AES-GCM encryption keyed by a group element |
| `src/fapake/modmath.py` | Modular arithmetic and the two groups (RFC 3526 2048-bit, toy demo group) |
| `src/fapake/wire.py` | Length-prefixed JSON messages over TCP |
| `src/fapake/server.py`, `client.py` | TCP server and interactive client |
| `src/fapake/trace.py` | Records every intermediate value of one run (feeds the visualizer) |
| `web/` | The visualizer: static page, Pyodide worker, local dev server |
| `development/` | Earlier experiments (Berlekamp-Welch decoding, brute force) |

## Security note

This is a research implementation, not audited software. What it does:

- The default group is the 2048-bit MODP group from RFC 3526.
- The server generates a new RSA key for oblivious transfer each time it starts (3072-bit, so it is larger than the group). The private key never leaves memory.
- All secrets and protocol randomness come from Python's `secrets` module.
- Session keys are 256-bit, derived with SHA-256 from the shared group element.
- Each connection has its own authentication session, so concurrent clients can't interfere with each other.

What it doesn't do:

- Passwords are 8 bits, so there are only 256 of them. Anyone holding a server record, or seeing a successful login, can try them all. Longer passwords need larger `n` in `Params`.
- Registration sends the password to the server in the clear, and the connection itself is not encrypted. Use it only on a trusted network, or put it behind TLS.
- Python's big-integer arithmetic is not constant-time.

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
Time taken for registration: 0.391179 seconds
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
SESSION KEY: 81b909a840c83c5c844f1af6babdf8a875392e957678fbf5ea078c8e1a755fa0
Time taken for authentication: 0.710440 seconds
```