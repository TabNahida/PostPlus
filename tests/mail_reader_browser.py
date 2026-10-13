#!/usr/bin/env python3
"""Serve synthetic browser mail checks on loopback; stop with Ctrl+C."""
import argparse
import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "/": ("tests/mail_reader_browser.html", "text/html; charset=utf-8"),
    "/browser-checks.js": ("tests/mail_reader_browser.js", "application/javascript"),
    "/mail-reader.js": ("web/mail-reader.js", "application/javascript"),
    "/mail-reader.css": ("web/mail-reader.css", "text/css"),
    "/style.css": ("web/style.css", "text/css"),
    "/i18n.js": ("web/i18n.js", "application/javascript"),
}
POLICY = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
          "connect-src 'self'; img-src 'self' data: https: http:; font-src 'self'; "
          "frame-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
PIXEL = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jw1sAAAAASUVORK5CYII=")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = self.path.split("?", 1)[0]
        if route == "/probe-count":
            body = json.dumps({"count": len(self.server.probes), "requests": self.server.probes}).encode()
            media = "application/json"
        elif route == "/probe.png":
            self.server.probes.append(self.path)
            body, media = PIXEL, "image/png"
        elif route in FILES:
            path, media = FILES[route]
            body = (ROOT / path).read_bytes()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        for name, value in (("Content-Type", media), ("Content-Length", str(len(body))),
                            ("Content-Security-Policy", POLICY), ("Cache-Control", "no-store"),
                            ("X-Content-Type-Options", "nosniff")):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    with HTTPServer(("127.0.0.1", args.port), Handler) as server:
        server.probes = []
        print(f"Open http://127.0.0.1:{server.server_port}/ for mail reader checks.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Browser checks stopped.", flush=True)
