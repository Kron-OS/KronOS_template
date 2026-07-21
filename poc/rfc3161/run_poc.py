#!/usr/bin/env python3
"""Verification-first PoC: RFC3161TimestampService against a REAL RFC 3161 TSA.

Section F workflow followed:
  1. Version pinned: rfc3161ng>=2.1.3 (pyproject.toml); installed 2.1.3 in
     ~/venv (confirmed below via importlib.metadata).
  2. Real TSA: the repo's own dev-compose `tsa` service
     (docker/docker-compose.dev.yml) is NOT a real RFC 3161 responder -- its
     inline python stub just returns a bare HTTP 200 with an
     application/timestamp-reply Content-Type header and an EMPTY body. That
     can never decode as a DER TimeStampResp, so it cannot exercise
     RFC3161TimestampService.verify() at all, and it isn't a meaningful test
     of .timestamp() either (any TSA-shaped client would "succeed" against
     it). Using it would be exactly the "confident-sounding, unverified"
     failure mode Section F exists to stop.
  3. Real substitute: `openssl ts`, following the exact pattern the repo
     already uses in tests/unit/test_tsa_round_trip.py for kronos_attest's
     TSAVerifier (a genuinely standards-following minimal TSA per
     `man openssl-ts`). This PoC exercises the OTHER component --
     RFC3161TimestampService.timestamp()/.verify() in
     src/application/timestamping.py -- which that existing test does not
     cover.
  4. This script spins up a throwaway CA + TSA cert, runs a real local HTTP
     server whose POST handler shells out to `openssl ts -reply` for every
     request (i.e. a real ASN.1-speaking TSA, not a stub), and drives the
     exact production class over real HTTP:
       - RFC3161TimestampService._build_timestamp_request() builds the
         real DER TimeStampReq.
       - RFC3161TimestampService.timestamp() POSTs it and gets back the
         openssl-issued DER TimeStampResp over the wire.
       - RFC3161TimestampService.verify() parses the real token and checks
         the embedded digest.
       - A wrong-digest negative test confirms verify() fails closed.

Run: ~/venv/bin/python3 poc/rfc3161/run_poc.py
"""

from __future__ import annotations

import asyncio
import hashlib
import http.server
import importlib.metadata
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.application.timestamping import (  # noqa: E402
    RFC3161TimestampService,
    _build_timestamp_request,
)
from src.exceptions import TimestampingError  # noqa: E402

TSA_HOST = "127.0.0.1"
TSA_PORT = 20318  # arbitrary local port for this throwaway PoC server


def log(msg: str) -> None:
    print(msg, flush=True)


def _run(*args: str) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True)  # noqa: S603
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {args}\nSTDOUT:{result.stdout}\nSTDERR:{result.stderr}")
    return result


def build_throwaway_tsa(workdir: Path) -> Path:
    """Build a throwaway CA + TSA cert/key and an openssl `ts` config file.

    Same technique as tests/unit/test_tsa_round_trip.py (already in this
    repo) -- a real, minimal, standards-following TSA per `man openssl-ts`.
    """
    ca_key, ca_pem = workdir / "ca.key", workdir / "ca.pem"
    tsa_key, tsa_csr, tsa_pem = workdir / "tsa.key", workdir / "tsa.csr", workdir / "tsa.pem"
    ext_cnf = workdir / "tsa_ext.cnf"
    ext_cnf.write_text("extendedKeyUsage=critical,timeStamping\n")

    _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(ca_key),
         "-out", str(ca_pem), "-days", "2", "-nodes", "-subj", "/CN=Test CA")
    _run("openssl", "req", "-newkey", "rsa:2048", "-keyout", str(tsa_key),
         "-out", str(tsa_csr), "-nodes", "-subj", "/CN=Test TSA")
    _run("openssl", "x509", "-req", "-in", str(tsa_csr), "-CA", str(ca_pem),
         "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(tsa_pem),
         "-days", "2", "-extfile", str(ext_cnf))

    tsa_cnf = workdir / "tsa.cnf"
    tsa_cnf.write_text(f"""\
[tsa]
default_tsa = tsa_config1

[tsa_config1]
dir = {workdir}
serial = {workdir}/tsaserial
crypto_device = builtin
signer_cert = {tsa_pem}
certs = {ca_pem}
signer_key = {tsa_key}
signer_digest = sha256
ess_cert_id_alg = sha256
default_policy = 1.2.3.4.5.6.7.8.1
digests = sha256
accuracy = secs:1
clock_precision_digits = 0
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
""")
    return tsa_cnf


def make_handler(tsa_cnf: Path, workdir: Path):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            req_der = self.rfile.read(length)
            log(f"[real-tsa-server] received {length}-byte POST "
                f"(Content-Type={self.headers.get('Content-Type')})")
            log(f"[real-tsa-server] request DER (hex): {req_der.hex()}")

            with tempfile.NamedTemporaryFile(dir=workdir, suffix=".tsq", delete=False) as reqf:
                reqf.write(req_der)
                req_path = reqf.name
            resp_path = req_path.replace(".tsq", ".tsr")

            result = subprocess.run(  # noqa: S603
                ["openssl", "ts", "-reply", "-config", str(tsa_cnf),
                 "-queryfile", req_path, "-out", resp_path],
                capture_output=True, text=True,
            )
            log(f"[real-tsa-server] openssl ts -reply exit={result.returncode} "
                f"stderr={result.stderr.strip()!r}")

            if result.returncode != 0:
                self.send_response(500)
                self.end_headers()
                return

            resp_der = Path(resp_path).read_bytes()
            log(f"[real-tsa-server] response DER (hex, truncated): {resp_der.hex()[:120]}...")
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(resp_der)))
            self.end_headers()
            self.wfile.write(resp_der)

        def log_message(self, fmt: str, *args) -> None:  # noqa: A002
            pass  # keep stdout to our own structured log() calls

    return Handler


async def main() -> int:
    log("=" * 70)
    log("PoC: RFC3161TimestampService <-> real RFC 3161 TSA responder")
    log("=" * 70)

    log(f"rfc3161ng version (pinned >=2.1.3 in pyproject.toml): "
        f"{importlib.metadata.version('rfc3161ng')}")
    if shutil.which("openssl") is None:
        log("FATAL: openssl binary not found on PATH")
        return 1
    log(f"openssl: {_run('openssl', 'version').stdout.strip()}")

    workdir = Path(tempfile.mkdtemp(prefix="kronos_poc_rfc3161_"))
    log(f"Scratch dir: {workdir}")
    tsa_cnf = build_throwaway_tsa(workdir)
    log("Built throwaway CA + TSA certificate/key + openssl ts config.")

    handler = make_handler(tsa_cnf, workdir)
    server = socketserver.ThreadingTCPServer((TSA_HOST, TSA_PORT), handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    log(f"Real local TSA responder listening on http://{TSA_HOST}:{TSA_PORT} "
        f"(each POST is answered by a real `openssl ts -reply` invocation).")

    try:
        svc = RFC3161TimestampService(tsa_url=f"http://{TSA_HOST}:{TSA_PORT}/")

        message = b"kronos rfc3161 poc: evidence merkle root anchor test"
        digest = hashlib.sha256(message).digest()
        log(f"\n--- Step 1: build request + POST via .timestamp() ---")
        log(f"digest (sha256): {digest.hex()}")

        req_der = _build_timestamp_request(digest)
        log(f"_build_timestamp_request() output (hex): {req_der.hex()}")

        token = await svc.timestamp(digest, hash_alg="sha256")
        log(f"RFC3161TimestampService.timestamp() returned {len(token)} bytes "
            f"of real DER TimeStampResp from the real TSA.")
        log(f"token (hex, truncated): {token.hex()[:160]}...")

        # Sanity: show openssl's own reading of the token, independent of
        # rfc3161ng, so we have a second real tool confirming the content.
        with tempfile.NamedTemporaryFile(dir=workdir, suffix=".tsr", delete=False) as tf:
            tf.write(token)
            token_path = tf.name
        text = subprocess.run(  # noqa: S603
            ["openssl", "ts", "-reply", "-in", token_path, "-text"],
            capture_output=True, text=True,
        )
        log("\n--- openssl's own independent decode of the returned token ---")
        log(text.stdout)

        log("--- Step 2: verify() the real token against the real digest ---")
        gen_time = await svc.verify(token, digest)
        log(f"RFC3161TimestampService.verify() succeeded. genTime = {gen_time!r}")
        assert gen_time is not None

        log("\n--- Step 3: negative test -- verify() must REJECT wrong digest ---")
        wrong_digest = hashlib.sha256(b"a completely different payload").digest()
        try:
            await svc.verify(token, wrong_digest)
            log("FAIL: verify() did NOT raise for a wrong digest -- this would be a bug!")
            return 1
        except TimestampingError as exc:
            log(f"verify() correctly raised TimestampingError: {exc}")

        log("\n--- Step 4: negative test -- .timestamp() against an unreachable TSA ---")
        from src.exceptions import StorageError
        bad_svc = RFC3161TimestampService(tsa_url=f"http://{TSA_HOST}:1/")
        try:
            await bad_svc.timestamp(digest)
            log("FAIL: timestamp() did not raise for an unreachable TSA")
            return 1
        except StorageError as exc:
            log(f".timestamp() correctly raised StorageError for unreachable TSA: {exc}")

        log("\n" + "=" * 70)
        log("PoC PASSED: real round trip (.timestamp() -> real TSA -> .verify())")
        log("confirmed correct, and both negative paths fail closed as designed.")
        log("=" * 70)
        return 0
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
