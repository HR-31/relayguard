#!/usr/bin/env python3
"""RelayGuard live demo server (Python stdlib only).

    python3 serve.py [--port 8723]

Serves the dashboard at / and exposes the REAL detector:
  GET  /api/dataset?tokens=&seed=   -> generate a labelled stream, reset the detector
  POST /api/score                   -> score ONE transaction (stream order expected)

The dashboard replays the stream through /api/score so what you see on screen is the
actual RelayDetector verdict, not a client-side reimplementation.
"""
import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from relayguard.detector import RelayDetector, FLAG_THRESHOLD
from relayguard.simulator import generate, summary

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")

# One detector per server process; reset whenever a fresh dataset is requested.
_detector = RelayDetector()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep the console quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            with open(os.path.join(STATIC, "index.html"), "rb") as fh:
                self._send(200, fh.read(), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/dataset":
            q = parse_qs(parsed.query)
            tokens = int(q.get("tokens", ["14"])[0])
            seed = int(q.get("seed", ["7"])[0])
            rows = generate(num_tokens=tokens, seed=seed)
            _detector.reset()
            payload = {
                "threshold": FLAG_THRESHOLD,
                "summary": summary(rows),
                "rows": rows,
            }
            self._send(200, json.dumps(payload))
            return
        self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/score":
            self._send(404, json.dumps({"error": "not found"}))
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            tx = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send(400, json.dumps({"error": "bad json"}))
            return
        result = _detector.score(tx)
        self._send(200, json.dumps(result.to_dict()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8723)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"RelayGuard demo running at http://127.0.0.1:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
