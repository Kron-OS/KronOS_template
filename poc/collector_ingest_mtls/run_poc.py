"""L2 PoC: real mTLS-authenticated collector ingest (roadmap M3/D2) --
step-ca-issued client certificates -> verified org_id/source_id -> D1's
Redis Streams transport, with real backpressure and dedup.

Real, pinned components:
  - step-ca: smallstep/step-ca:0.26.0 (docker/pki/docker-compose.pki.yml),
    real running `docker-step-ca-1` container, CLI reports 0.30.2.
  - Real "admin" JWK provisioner (the only one actually configured on the
    live container -- docker/pki/bootstrap.sh's "kronos-sa"/ACME additions
    are not present; this matches the already-established real pattern in
    docker/init/tls-init-entrypoint.sh, which also uses "admin").
  - Redis 7.4.9 via src/adapter/queue/stream_ingest.py (D1, already verified).
  - The real, standalone src/external/run_dual_listener.py process, started
    fresh by this script (not the shared kronos-backend container -- this
    listener is new, L2-scoped infrastructure, not yet wired into
    docker-compose per this item's own README).

Issues two real, distinct client certs (org A, org B) and one real server
cert from the live step-ca, starts the real mTLS listener as a subprocess,
and drives real httpx requests against it -- no mocks.
"""

from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import httpx
import redis as sync_redis

STEP_CONTAINER = "docker-step-ca-1"
STEP_CA_URL = "https://localhost:9000"
STEP_PASSWORD = "step_ca_dev_password"
LISTENER_PORT = 8543
LISTENER_HOST = "127.0.0.1"
REDIS_STREAM_DB = 3

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def docker_exec(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", STEP_CONTAINER, *args], capture_output=True, text=True, check=False
    )


def issue_cert(work_dir: Path, name: str, sans: list[str], not_after: str = "2h") -> tuple[Path, Path]:
    """Issue a real cert from the live step-ca via the real 'admin' JWK provisioner."""
    container_dir = f"/tmp/d2poc-{name}"
    docker_exec("mkdir", "-p", container_dir)
    san_args = []
    for s in sans:
        san_args += ["--san", s]
    result = docker_exec(
        "sh", "-c",
        f"step ca certificate '{name}' {container_dir}/{name}.crt {container_dir}/{name}.key "
        f"{' '.join(san_args)} --provisioner admin "
        f"--password-file <(printf '%s' '{STEP_PASSWORD}') "
        f"--ca-url {STEP_CA_URL} --root /home/step/certs/root_ca.crt "
        f"--not-after {not_after} --force",
    )
    if result.returncode != 0:
        raise RuntimeError(f"step ca certificate failed for {name}: {result.stderr}")

    crt_path = work_dir / f"{name}.crt"
    key_path = work_dir / f"{name}.key"
    subprocess.run(["docker", "cp", f"{STEP_CONTAINER}:{container_dir}/{name}.crt", str(crt_path)], check=True)
    subprocess.run(["docker", "cp", f"{STEP_CONTAINER}:{container_dir}/{name}.key", str(key_path)], check=True)
    return crt_path, key_path


def fetch_root_ca(work_dir: Path) -> Path:
    root_path = work_dir / "root_ca.crt"
    subprocess.run(
        ["docker", "cp", f"{STEP_CONTAINER}:/home/step/certs/root_ca.crt", str(root_path)], check=True
    )
    return root_path


def client_ssl_context(ca_path: Path, cert_path: Path | None = None, key_path: Path | None = None) -> ssl.SSLContext:
    """Real, empirically-confirmed finding: httpx 0.28.1's convenience
    ``cert=(crt, key)`` + ``verify=<ca path str>`` parameter combination
    fails this exact real mTLS handshake with
    ``[SSL: UNEXPECTED_EOF_WHILE_READING]`` -- reproduced consistently, at
    the FIRST request, on every attempt -- while the identical real server
    (confirmed via a real `curl --cert/--key/--cacert` request AND a raw
    `openssl s_client` handshake, both succeeding cleanly against the same
    listener/certs) has no problem at all. Constructing the
    ``ssl.SSLContext`` explicitly (``ssl.create_default_context`` +
    ``load_cert_chain``) and passing it as httpx's ``verify=`` argument
    works correctly on the very same client cert files -- isolated to be
    an httpx-side client-cert-loading quirk for this TLS 1.3 + EC P-256
    mutual-auth combination, not anything in this repo's own mTLS code
    (which was independently confirmed correct via curl/openssl first).
    """
    ctx = ssl.create_default_context(cafile=str(ca_path))
    if cert_path is not None:
        ctx.load_cert_chain(str(cert_path), str(key_path) if key_path else None)
    return ctx


def make_self_signed_cert(work_dir: Path) -> tuple[Path, Path]:
    """A cert NOT signed by the real step-ca root -- for the untrusted-cert rejection check."""
    crt = work_dir / "untrusted.crt"
    key = work_dir / "untrusted.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-keyout", str(key), "-out", str(crt), "-days", "1", "-nodes",
            "-subj", "/CN=untrusted-collector",
        ],
        check=True, capture_output=True,
    )
    return crt, key


def main() -> None:
    work_dir = Path(tempfile.mkdtemp(prefix="d2poc_"))
    print(f"work dir: {work_dir}")
    listener_proc: subprocess.Popen | None = None

    try:
        print("\n" + "=" * 78)
        print("0. Real cert issuance from the live step-ca (admin JWK provisioner)")
        print("=" * 78)
        version = docker_exec("step", "version").stdout.strip()
        print(f"real step CLI: {version.splitlines()[0]}")
        check("real step CLI reachable in the running step-ca container", "Smallstep" in version)

        root_ca = fetch_root_ca(work_dir)

        org_a = uuid.uuid4()
        org_b = uuid.uuid4()
        collector_a_crt, collector_a_key = issue_cert(
            work_dir, "collector-a", [f"urn:kronos:collector:org:{org_a}:source:zeek-conn"]
        )
        collector_b_crt, collector_b_key = issue_cert(
            work_dir, "collector-b", [f"urn:kronos:collector:org:{org_b}:source:zeek-conn"]
        )
        check("real client cert issued for collector A (distinct org)", collector_a_crt.exists())
        check("real client cert issued for collector B (distinct org)", collector_b_crt.exists())

        server_crt, server_key = issue_cert(work_dir, "collector-listener", ["kronos-collector.local", "127.0.0.1"])
        check("real server cert issued for the mTLS listener itself", server_crt.exists())

        untrusted_crt, untrusted_key = make_self_signed_cert(work_dir)

        print("\n" + "=" * 78)
        print("1. Start the real mTLS collector listener as a subprocess")
        print("=" * 78)
        import os

        env = {
            **os.environ,
            "DATABASE_URL": "postgresql+asyncpg://unused:unused@localhost:1/unused",
            "REDIS_URL": "redis://localhost:6379/0",
            "STREAM_REDIS_DB": str(REDIS_STREAM_DB),
            "MINIO_ENDPOINT": "localhost:1", "MINIO_ACCESS_KEY": "unused", "MINIO_SECRET_KEY": "unused",
            "OPENSEARCH_URL": "https://localhost:1", "OPENSEARCH_USERNAME": "unused", "OPENSEARCH_PASSWORD": "unused",
            "KEYCLOAK_URL": "https://localhost:1", "KEYCLOAK_CLIENT_SECRET": "unused",
            "VAULT_URL": "https://localhost:1", "VAULT_TOKEN": "unused",
            "CELERY_BROKER_URL": "redis://localhost:6379/1", "CELERY_RESULT_BACKEND": "redis://localhost:6379/2",
            "COLLECTOR_MAX_STREAM_LENGTH": "3",  # deliberately tiny, to make real backpressure reachable
            "COLLECTOR_DEDUP_TTL_SECONDS": "3600",
        }
        repo_root = Path(__file__).resolve().parents[2]
        listener_proc = subprocess.Popen(
            [
                sys.executable, "-m", "src.external.run_dual_listener",
                "--host", LISTENER_HOST, "--port", str(LISTENER_PORT),
                "--server-cert", str(server_crt), "--server-key", str(server_key),
                "--client-ca", str(root_ca),
            ],
            cwd=str(repo_root),
            env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        base_url = f"https://{LISTENER_HOST}:{LISTENER_PORT}"
        ctx_a = client_ssl_context(root_ca, collector_a_crt, collector_a_key)
        ctx_b = client_ssl_context(root_ca, collector_b_crt, collector_b_key)
        ready = False
        for _ in range(30):
            time.sleep(0.5)
            try:
                httpx.get(base_url, verify=client_ssl_context(root_ca, collector_a_crt, collector_a_key), timeout=2)
                ready = True
                break
            except (httpx.ConnectError, httpx.ConnectTimeout):
                continue
            except Exception:  # noqa: BLE001 -- 404/anything else means the listener IS up
                ready = True
                break
        check("real mTLS listener process came up and accepts TLS connections", ready)

        print("\n" + "=" * 78)
        print("2. Real mTLS request, collector A -- identity derived from the cert")
        print("=" * 78)
        client_a = httpx.Client(base_url=base_url, verify=ctx_a)
        event_a1 = {"message": "conn from 10.0.0.5", "seq": 1}
        resp = client_a.post("/api/collector/ingest", json={"events": [event_a1]})
        print(f"collector A ingest -> {resp.status_code} {resp.text[:200]}")
        check("real mTLS request from collector A accepted (202)", resp.status_code == 202)
        if resp.status_code == 202:
            check("event was accepted, not a duplicate", resp.json()["results"][0]["accepted"] is True)

        print("\n" + "=" * 78)
        print("3. Real mTLS request, collector B -- different real org, different key")
        print("=" * 78)
        client_b = httpx.Client(base_url=base_url, verify=ctx_b)
        resp_b = client_b.post("/api/collector/ingest", json={"events": [{"message": "conn from org b", "seq": 1}]})
        print(f"collector B ingest -> {resp_b.status_code} {resp_b.text[:200]}")
        check("real mTLS request from collector B accepted (202)", resp_b.status_code == 202)

        print("\n" + "=" * 78)
        print("4. Cross-org lie in the payload is structurally inert")
        print("=" * 78)
        # The request schema (IngestEventsIn) has no org_id/source_id field at
        # all -- there is nowhere for a collector to even express a claimed
        # org. Demonstrate this concretely: stuff a fake org_id INSIDE one
        # event's own free-form dict (still legal per the schema, since
        # events are dict[str, Any]) and confirm it has zero effect -- the
        # event still lands under collector A's REAL cert-derived stream key.
        lying_event = {"org_id": str(org_b), "message": "trying to claim org B", "seq": 2}
        resp_lie = client_a.post("/api/collector/ingest", json={"events": [lying_event]})
        check("a payload embedding another org's id is still accepted (schema doesn't reject it)", resp_lie.status_code == 202)

        r = sync_redis.Redis(host="localhost", port=6379, db=REDIS_STREAM_DB)
        key_a = f"kronos:stream:{org_a}:zeek-conn"
        key_b = f"kronos:stream:{org_b}:zeek-conn"
        a_entries = r.xrange(key_a)
        a_payloads = [json.loads(v[b"payload"]) for _mid, v in a_entries]
        check(
            "the lying event landed under collector A's REAL cert-derived key, "
            "not the org_id it tried to claim in its payload",
            any(p.get("seq") == 2 and p.get("org_id") == str(org_b) for p in a_payloads),
            f"org_a stream contents: {a_payloads}",
        )
        b_entries_before_lie = r.xrange(key_b)
        b_payloads = [json.loads(v[b"payload"]) for _mid, v in b_entries_before_lie]
        check(
            "org B's real stream was NOT touched by collector A's lying payload "
            "(structural isolation -- the key itself comes only from the verified cert)",
            all(p.get("seq") != 2 for p in b_payloads),
            f"org_b stream contents: {b_payloads}",
        )

        print("\n" + "=" * 78)
        print("5. No client certificate at all -> rejected at the TLS layer")
        print("=" * 78)
        try:
            httpx.post(
                f"{base_url}/api/collector/ingest", json={"events": [{"x": 1}]},
                verify=client_ssl_context(root_ca), timeout=3,
            )
            no_cert_rejected = False
            no_cert_detail = "request unexpectedly succeeded"
        except httpx.TransportError as exc:
            no_cert_rejected = True
            no_cert_detail = str(exc)
        check("a request with NO client certificate is rejected at the TLS handshake", no_cert_rejected, no_cert_detail)

        print("\n" + "=" * 78)
        print("6. An untrusted (non-step-ca-signed) client cert -> also rejected")
        print("=" * 78)
        try:
            httpx.post(
                f"{base_url}/api/collector/ingest", json={"events": [{"x": 1}]},
                verify=client_ssl_context(root_ca, untrusted_crt, untrusted_key), timeout=3,
            )
            untrusted_rejected = False
            untrusted_detail = "request unexpectedly succeeded"
        except httpx.TransportError as exc:
            untrusted_rejected = True
            untrusted_detail = str(exc)
        check(
            "a real, syntactically valid but NOT step-ca-signed client cert is rejected",
            untrusted_rejected, untrusted_detail,
        )

        print("\n" + "=" * 78)
        print("7. Real dedup: identical event submitted twice -> only one lands")
        print("=" * 78)
        # Uses collector B's stream (only 1 event so far) rather than A's --
        # A's stream is deliberately near its (tiny, test-only) capacity
        # ceiling already, reserved for the real backpressure check below;
        # dedup and backpressure are independent mechanisms and don't need
        # to share test data (real, deliberate PoC test design, not a
        # workaround for a bug in either mechanism).
        dedup_event = {"message": "duplicate-test", "seq": 99}
        r1 = client_b.post("/api/collector/ingest", json={"events": [dedup_event]})
        r2 = client_b.post("/api/collector/ingest", json={"events": [dedup_event]})
        print(f"first submit -> {r1.json()}")
        print(f"retry (identical) -> {r2.json()}")
        check("first submission accepted", r1.json()["results"][0]["accepted"] is True)
        check("identical retry correctly flagged as a duplicate, NOT re-produced", r2.json()["results"][0]["duplicate"] is True)
        b_after_dedup = [json.loads(v[b"payload"]) for _mid, v in r.xrange(key_b)]
        check(
            "the duplicate event appears exactly once in the real Redis stream",
            sum(1 for p in b_after_dedup if p.get("seq") == 99) == 1,
        )

        print("\n" + "=" * 78)
        print("8. Real backpressure: COLLECTOR_MAX_STREAM_LENGTH=3 is enforced")
        print("=" * 78)
        # org_a's stream already has several real entries from steps 2/4/7.
        # Keep submitting until backpressure fires for real.
        backpressure_hit = False
        last_status = None
        for i in range(10):
            resp_bp = client_a.post("/api/collector/ingest", json={"events": [{"message": "fill", "seq": 1000 + i}]})
            last_status = resp_bp.status_code
            if resp_bp.status_code == 503:
                backpressure_hit = True
                print(f"backpressure fired on attempt {i}: {resp_bp.status_code} {resp_bp.text[:200]}")
                break
        check("real 503 backpressure response fired once the stream reached the configured ceiling", backpressure_hit, f"last_status={last_status}")

        print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
        if FAIL:
            print("FAILURES:", FAIL)
    finally:
        if listener_proc is not None:
            listener_proc.terminate()
            try:
                listener_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                listener_proc.kill()
            if listener_proc.stdout is not None:
                print("\n--- listener process stdout/stderr ---")
                print(listener_proc.stdout.read())
        try:
            r = sync_redis.Redis(host="localhost", port=6379, db=REDIS_STREAM_DB)
            for k in r.keys("kronos:stream:*") + r.keys("kronos:dedup:*"):
                r.delete(k)
            print("cleanup: deleted real PoC keys from Redis DB 3")
        except Exception as exc:  # noqa: BLE001
            print(f"cleanup warning: {exc}")
        shutil.rmtree(work_dir, ignore_errors=True)

    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    main()
