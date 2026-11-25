"""Local dev server for the visualizer.

    uv run python web/serve.py            # then open http://localhost:8000

Serves web/ at the root and src/fapake/ at /fapake/, the same layout the GitHub Pages
workflow builds. The page's ?selftest mode reports to POST /__log (printed here) and
uploads static snapshots of the rendered page to /__snapshot/<name> for screenshots.
"""

import argparse
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PACKAGE = ROOT.parent / "src" / "fapake"
SNAPSHOTS: dict[str, bytes] = {}


class Handler(SimpleHTTPRequestHandler):
    def translate_path(self, path: str) -> str:
        clean = path.split("?", 1)[0].split("#", 1)[0]
        if clean.startswith("/fapake/"):
            name = Path(clean).name
            return str(PACKAGE / name)
        return super().translate_path(path)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self) -> None:
        if self.path.startswith("/__phone/"):
            # A snapshot framed at phone width (desktop windows can't be made that narrow).
            name = self.path.rsplit("/", 1)[-1]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f'<body style="margin:0"><iframe src="/__snapshot/{name}" '
                             f'style="border:0;width:380px;height:100vh"></iframe>'.encode())
            return
        if self.path.startswith("/__snapshot/"):
            body = SNAPSHOTS.get(self.path.rsplit("/", 1)[-1])
            if body is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/__log":
            print(body.decode(errors="replace"), flush=True)
        elif self.path.startswith("/__snapshot/"):
            # A static copy of the rendered page, so a headless browser can screenshot it.
            SNAPSHOTS[self.path.rsplit("/", 1)[-1]] = body
        else:
            self.send_error(404)
            return
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        if "--quiet" not in sys.argv:
            super().log_message(format, *args)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--quiet", action="store_true", help="don't log each request")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), partial(Handler, directory=str(ROOT)))
    print(f"Visualizer running at http://localhost:{args.port}  (Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
