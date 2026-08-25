#!/usr/bin/env python3
"""Real RFC 3161 TSA responder for test-environment use only.

Every POST is answered by shelling out to a real `openssl ts -reply`
invocation, producing a genuine ASN.1-signed DER TimeStampResp per request --
not canned, not a stub. This is the exact technique proven end-to-end against
the real production RFC3161TimestampService in poc/rfc3161/run_poc.py
(see that PoC's README for why the FreeTSA Docker image this replaced does
not exist on Docker Hub, and why the dev-compose stub -- a bare HTTP 200 with
an empty body -- can never decode as a real TimeStampResp).

Never used in production: the CA/TSA cert here is a throwaway, freshly
generated at container startup, trusted by nothing outside this test
environment.
"""

from __future__ import annotations

import http.server
import os
import socketserver
import subprocess
import sys
import tempfile
from pathlib import Path

TSA_CNF = Path(os.environ.get("TSA_CONFIG", "/tsa/tsa.cnf"))
WORKDIR = TSA_CNF.parent
PORT = int(os.environ.get("TSA_PORT", "318"))


def log(msg: str) -> None:
    print(msg, flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        req_der = self.rfile.read(length)

        with tempfile.NamedTemporaryFile(dir=WORKDIR, suffix=".tsq", delete=False) as reqf:
            reqf.write(req_der)
            req_path = reqf.name
        resp_path = req_path.replace(".tsq", ".tsr")

        result = subprocess.run(  # noqa: S603
            [
                "openssl",
                "ts",
                "-reply",
                "-config",
                str(TSA_CNF),
                "-queryfile",
                req_path,
                "-out",
                resp_path,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            log(f"openssl ts -reply failed: {result.stderr.strip()!r}")
            self.send_response(500)
            self.end_headers()
            return

        resp_der = Path(resp_path).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(resp_der)))
        self.end_headers()
        self.wfile.write(resp_der)

    def do_GET(self) -> None:  # noqa: N802
        # Real compose healthcheck target -- confirms the responder process
        # itself is up without needing a full timestamp round-trip.
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A002
        log(f"[tsa-mock] {self.address_string()} - {fmt % args}")


def main() -> int:
    if not TSA_CNF.exists():
        log(f"FATAL: {TSA_CNF} not found -- entrypoint must generate it first")
        return 1
    log(f"Real RFC 3161 TSA responder (openssl ts) listening on 0.0.0.0:{PORT}")
    server = socketserver.ThreadingTCPServer(("0.0.0.0", PORT), Handler)  # noqa: S104
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
