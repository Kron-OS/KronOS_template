#!/usr/bin/env python3
"""Verification-first PoC: BatchSealingService against REAL Redis, MinIO,
Postgres, and a real RFC 3161 TSA responder (roadmap M3/D3, GATE item).

Pinned versions (read from this repo / this host, not assumed):
  - redis server: real running `docker-redis-1` (image redis:7-alpine),
    `INFO server` reports 7.4.9. Python client `redis` 8.0.1 (already
    confirmed in poc/stream_ingest_redis/).
  - Postgres: real running `docker-postgres-1` (postgres:16-alpine),
    `postgres --version` reports 16.14. `sqlalchemy` 2.0.51, `asyncpg` 0.31.0.
  - MinIO: real running `docker-minio-1` (minio/minio:latest),
    RELEASE.2025-09-07T16-13-09Z. `boto3` 1.43.46.
  - RFC 3161 TSA: see poc/rfc3161/README.md's finding -- the dev-compose
    `tsa` service is an empty-body HTTP 200 stub, not a real ASN.1 TSA. This
    PoC reuses that PoC's real substitute instead: a local HTTP server whose
    POST handler shells out to a real `openssl ts -reply` invocation against
    a throwaway CA+TSA cert, producing genuine DER TimeStampToken bytes.
    `rfc3161ng` 2.1.3 (confirmed via importlib.metadata below).

This script exercises the real, unmodified production classes:
  src/adapter/queue/stream_ingest.py     -- RedisStreamIngestAdapter
  src/adapter/repository/postgres_sealed_batch.py -- PostgresSealedBatchRepository
  src/adapter/repository/postgres_audit_log.py    -- PostgresAuditLogRepository
  src/adapter/storage/sealed_batch_storage.py     -- S3SealedBatchStorage
  src/application/timestamping.py        -- RFC3161TimestampService
  src/application/batch_sealing.py       -- BatchSealingService
  src/application/sealing_trigger_policy.py -- SizeBoundTriggerPolicy
  src/application/audit_log.py           -- AuditLogService
  src/domain/merkle.py                   -- build_merkle_root/merkle_proof/verify_proof

Three scenarios, each against real dependencies:
  1. Happy path: seal a real batch, verify the WORM object/TSA token/Postgres
     row/audit event are all real, then demonstrate the literal GATE
     condition -- reconstruct an inclusion proof for an ARBITRARY event from
     the batch's own persisted Postgres row and verify it (positive), and
     show a tampered leaf/proof is rejected (negative).
  2. Sealing failure must never ack the stream: force a real MinIO failure
     (wrong credentials -> real S3 ClientError), confirm the source events
     remain in the consumer group's PEL (real XPENDING check), then recover
     with correct credentials and confirm the *same* events get sealed via
     D1's reclaim_stale(min_idle_ms=0) mechanism -- no data lost, no
     duplication.
  3. A MAXLEN trim of unsealed events must page, not warn: seal one batch,
     leave further events unsealed, real XTRIM past the sealed watermark,
     and confirm seal_pending() raises EvidenceLossDetectedError with a real
     BATCH_SEAL_WATERMARK_GAP_DETECTED audit event persisted in Postgres.

Run: ~/venv/bin/python3 poc/batch_sealing/run_poc.py
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
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from redis.asyncio import Redis as AsyncRedis  # noqa: E402
from sqlalchemy import text as sa_text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_sealed_batch import PostgresSealedBatchRepository  # noqa: E402
from src.adapter.storage.sealed_batch_storage import S3SealedBatchStorage  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.batch_sealing import BatchSealingService  # noqa: E402
from src.application.sealing_trigger_policy import SizeBoundTriggerPolicy  # noqa: E402
from src.application.timestamping import RFC3161TimestampService  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.merkle import merkle_proof, verify_proof  # noqa: E402
from src.exceptions import BatchSealFailedError, EvidenceLossDetectedError  # noqa: E402

REDIS_DSN = "redis://localhost:6379/3"
DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
MINIO_ENDPOINT = "http://localhost:9000"
MINIO_ACCESS_KEY = "kronos_minio"
MINIO_SECRET_KEY = "kronos_minio_dev_password"

TSA_HOST = "127.0.0.1"
TSA_PORT = 20319  # distinct from poc/rfc3161's 20318, avoids any port clash

CHECKS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}", flush=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def _run(*args: str) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True)  # noqa: S603
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {args}\nSTDOUT:{result.stdout}\nSTDERR:{result.stderr}")
    return result


def build_throwaway_tsa(workdir: Path) -> Path:
    """Identical technique to poc/rfc3161/run_poc.py's build_throwaway_tsa --
    a real, minimal, standards-following TSA per `man openssl-ts`, not a stub."""
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
            with tempfile.NamedTemporaryFile(dir=workdir, suffix=".tsq", delete=False) as reqf:
                reqf.write(req_der)
                req_path = reqf.name
            resp_path = req_path.replace(".tsq", ".tsr")
            result = subprocess.run(  # noqa: S603
                ["openssl", "ts", "-reply", "-config", str(tsa_cnf),
                 "-queryfile", req_path, "-out", resp_path],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                self.send_response(500)
                self.end_headers()
                return
            resp_der = Path(resp_path).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(resp_der)))
            self.end_headers()
            self.wfile.write(resp_der)

        def log_message(self, fmt: str, *args) -> None:  # noqa: A002
            pass

    return Handler


async def main() -> int:
    log("=" * 78)
    log("PoC: BatchSealingService <-> real Redis + MinIO + Postgres + real TSA")
    log("=" * 78)
    log(f"rfc3161ng version (pinned rfc3161ng>=2.1.3): {importlib.metadata.version('rfc3161ng')}")
    if shutil.which("openssl") is None:
        log("FATAL: openssl binary not found on PATH")
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="kronos_poc_batch_sealing_"))
    tsa_cnf = build_throwaway_tsa(workdir)
    handler = make_handler(tsa_cnf, workdir)
    server = socketserver.ThreadingTCPServer((TSA_HOST, TSA_PORT), handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    log(f"Real local TSA responder listening on http://{TSA_HOST}:{TSA_PORT} "
        f"(every POST answered by a real `openssl ts -reply` invocation).")

    redis = AsyncRedis.from_url(REDIS_DSN)
    engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
    await PostgresSealedBatchRepository.create_tables(engine)
    log("Real Postgres: sealed_batches table created (checkfirst=True).")

    stream_adapter = RedisStreamIngestAdapter(redis)
    repository = PostgresSealedBatchRepository(engine)
    audit_repo = PostgresAuditLogRepository(engine)
    audit_log = AuditLogService(audit_repo)
    tsa_service = RFC3161TimestampService(tsa_url=f"http://{TSA_HOST}:{TSA_PORT}/")
    good_storage = S3SealedBatchStorage(
        endpoint_url=MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        bucket_prefix="kronos-poc-batch-seal",
        retention_days=1,  # short retention for the PoC; still real COMPLIANCE mode
    )

    try:
        info = await redis.info("server")
        log(f"redis_version = {info.get('redis_version')}")
        check("Redis server reports version 7.x", str(info.get("redis_version", "")).startswith("7."))

        # -----------------------------------------------------------------
        # Scenario 1: happy path + the literal GATE condition
        # -----------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO 1: seal a real batch; demonstrate a real inclusion proof")
        log("=" * 78)

        org_1 = uuid.uuid4()
        source_1 = "poc-zeek-conn"
        service_1 = BatchSealingService(
            stream_adapter, good_storage, tsa_service, audit_log, repository,
            SizeBoundTriggerPolicy(max_events=5),
            consumer_name="poc-sealer-1",
        )

        payloads = [f'{{"event":"conn","seq":{i}}}'.encode() for i in range(5)]
        for p in payloads:
            await stream_adapter.produce(org_1, source_1, p)
        log(f"Produced {len(payloads)} real events onto kronos:stream:{org_1}:{source_1}")

        sealed = await service_1.seal_pending(org_1, source_1)
        check("seal_pending() returned a SealedBatch", sealed is not None)
        assert sealed is not None
        log(f"batch_id={sealed.batch_id} event_count={sealed.event_count} "
            f"merkle_root={sealed.merkle_root}")
        check("event_count matches produced events", sealed.event_count == 5)

        expected_leaves = [hashlib.sha256(p).hexdigest() for p in payloads]
        check("leaf_hashes match real sha256(payload) in order",
              list(sealed.leaf_hashes) == expected_leaves)

        # Real WORM object round trip against real MinIO.
        manifest_bytes = await good_storage.get_batch(sealed.worm_bucket, sealed.worm_object_key)
        import json as _json
        manifest = _json.loads(manifest_bytes)
        check("real WORM manifest read back from MinIO matches batch_id",
              manifest["batch_id"] == str(sealed.batch_id))
        check("real WORM manifest event_count matches", manifest["event_count"] == 5)
        lock_cfg = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: good_storage._client.get_object_lock_configuration(Bucket=sealed.worm_bucket),
        )
        check(
            "real MinIO bucket has Object Lock ENABLED + COMPLIANCE default retention",
            lock_cfg["ObjectLockConfiguration"]["ObjectLockEnabled"] == "Enabled"
            and lock_cfg["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]["Mode"] == "COMPLIANCE",
        )

        # Real TSA token round trip: independently decode with openssl, then
        # verify via the real RFC3161TimestampService.verify().
        assert sealed.tsa_token is not None
        with tempfile.NamedTemporaryFile(dir=workdir, suffix=".tsr", delete=False) as tf:
            tf.write(sealed.tsa_token)
            token_path = tf.name
        openssl_decode = subprocess.run(  # noqa: S603
            ["openssl", "ts", "-reply", "-in", token_path, "-text"],
            capture_output=True, text=True,
        )
        log("\n--- openssl's own independent decode of the real TSA token ---")
        log(openssl_decode.stdout)
        check("openssl independently decodes the real TSA token (Status: Granted)",
              "Status: Granted" in openssl_decode.stdout)

        gen_time = await tsa_service.verify(sealed.tsa_token, bytes.fromhex(sealed.merkle_root))
        check("RFC3161TimestampService.verify() confirms the token covers the real merkle_root",
              gen_time is not None)
        log(f"TSA genTime = {gen_time!r}")

        # Real Postgres row, fetched independently via raw SQL (not just the
        # repository's own round trip) to prove it is really durable.
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    sa_text("SELECT batch_id, merkle_root, event_count FROM sealed_batches WHERE batch_id = :b"),
                    {"b": str(sealed.batch_id)},
                )
            ).one_or_none()
        check("real Postgres row exists (raw SQL, independent of the repository)", row is not None)
        if row is not None:
            check("raw SQL row's merkle_root matches", row.merkle_root == sealed.merkle_root)

        # Real audit event, fetched independently via raw SQL.
        async with engine.connect() as conn:
            audit_row = (
                await conn.execute(
                    sa_text(
                        "SELECT event_type, details FROM audit_log WHERE org_id = :o "
                        "AND event_type = :t ORDER BY sequence_number DESC LIMIT 1"
                    ),
                    {"o": str(org_1), "t": AuditEventType.BATCH_SEALED.value},
                )
            ).one_or_none()
        check("real BATCH_SEALED audit event persisted in Postgres audit_log", audit_row is not None)

        # The literal GATE condition: reconstruct an inclusion proof for an
        # ARBITRARY event straight from the real, freshly-refetched Postgres
        # row (not the in-process object) and verify it.
        refetched = await repository.get_by_id(sealed.batch_id, org_1)
        check("SealedBatch re-fetched fresh from real Postgres", refetched is not None)
        assert refetched is not None

        arbitrary_index = 2  # "an arbitrary event" -- the middle one, not index 0
        leaf = refetched.leaf_hashes[arbitrary_index]
        proof = merkle_proof(list(refetched.leaf_hashes), arbitrary_index)
        positive = verify_proof(leaf, proof, refetched.merkle_root)
        check(
            f"GATE: real inclusion proof for arbitrary event index={arbitrary_index} "
            f"(message_id={refetched.message_ids[arbitrary_index]}) verifies TRUE",
            positive,
        )

        tampered_leaf = hashlib.sha256(b"not-the-real-event").hexdigest()
        negative_leaf = verify_proof(tampered_leaf, proof, refetched.merkle_root)
        check("GATE negative: tampered leaf against the real proof verifies FALSE", not negative_leaf)

        tampered_proof = [(hashlib.sha256(b"bogus-sibling").hexdigest(), "right")]
        negative_proof = verify_proof(leaf, tampered_proof, refetched.merkle_root)
        check("GATE negative: tampered proof against the real leaf verifies FALSE", not negative_proof)

        # Consumer group PEL must be empty -- everything was really acked.
        pending_info = await redis.xpending(f"kronos:stream:{org_1}:{source_1}", "kronos-sealer")
        check("real XPENDING shows 0 pending entries after successful seal (fully acked)",
              pending_info["pending"] == 0)

        # -----------------------------------------------------------------
        # Scenario 2: sealing failure must never ack the stream
        # -----------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO 2: a real MinIO failure must leave events unacked, then recover")
        log("=" * 78)

        org_2 = uuid.uuid4()
        source_2 = "poc-failing-source"
        broken_storage = S3SealedBatchStorage(
            endpoint_url=MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key="wrong-secret-key-on-purpose",
            bucket_prefix="kronos-poc-batch-seal",
            retention_days=1,
        )
        service_2_broken = BatchSealingService(
            stream_adapter, broken_storage, tsa_service, audit_log, repository,
            SizeBoundTriggerPolicy(max_events=2),
            consumer_name="poc-sealer-2",
        )
        failed_id_1 = await stream_adapter.produce(org_2, source_2, b"will-fail-1")
        failed_id_2 = await stream_adapter.produce(org_2, source_2, b"will-fail-2")

        raised = False
        try:
            await service_2_broken.seal_pending(org_2, source_2)
        except BatchSealFailedError as exc:
            raised = True
            log(f"seal_pending() correctly raised BatchSealFailedError: {exc}")
        check("real MinIO auth failure raises BatchSealFailedError (not swallowed)", raised)

        pending_info_2 = await redis.xpending(f"kronos:stream:{org_2}:{source_2}", "kronos-sealer")
        check(
            "after the real failure, both events are STILL pending (unacked) per real XPENDING",
            pending_info_2["pending"] == 2,
        )
        async with engine.connect() as conn:
            fail_audit = (
                await conn.execute(
                    sa_text(
                        "SELECT event_type FROM audit_log WHERE org_id = :o "
                        "AND event_type = :t ORDER BY sequence_number DESC LIMIT 1"
                    ),
                    {"o": str(org_2), "t": AuditEventType.BATCH_SEAL_FAILED.value},
                )
            ).one_or_none()
        check("real BATCH_SEAL_FAILED audit event persisted in Postgres", fail_audit is not None)
        assert await repository.get_last_sealed(org_2, source_2) is None
        check("no SealedBatch row was ever persisted for the failed attempt", True)

        # Recovery: same consumer, correct storage this time. D1's
        # reclaim_stale(min_idle_ms=0) must re-collect the still-pending
        # events (they were delivered to THIS consumer name already) and
        # seal them for real -- no data lost, nothing duplicated.
        service_2_recovered = BatchSealingService(
            stream_adapter, good_storage, tsa_service, audit_log, repository,
            SizeBoundTriggerPolicy(max_events=2),
            consumer_name="poc-sealer-2",
        )
        recovered = await service_2_recovered.seal_pending(org_2, source_2)
        check("recovery: seal_pending() with correct storage now succeeds", recovered is not None)
        assert recovered is not None
        check("recovery: sealed exactly the 2 originally-failed events, not more/fewer",
              recovered.event_count == 2
              and set(recovered.message_ids) == {failed_id_1, failed_id_2})

        pending_info_2b = await redis.xpending(f"kronos:stream:{org_2}:{source_2}", "kronos-sealer")
        check("recovery: real XPENDING now shows 0 pending (recovered events acked)",
              pending_info_2b["pending"] == 0)

        # -----------------------------------------------------------------
        # Scenario 3: MAXLEN trim of unsealed events must page, not warn
        # -----------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO 3: real MAXLEN trim past the sealed watermark must page")
        log("=" * 78)

        org_3 = uuid.uuid4()
        source_3 = "poc-trim-source"
        service_3 = BatchSealingService(
            stream_adapter, good_storage, tsa_service, audit_log, repository,
            SizeBoundTriggerPolicy(max_events=2),
            consumer_name="poc-sealer-3",
        )
        for i in range(2):
            await stream_adapter.produce(org_3, source_3, f"batch-a-{i}".encode())
        batch_a = await service_3.seal_pending(org_3, source_3)
        check("scenario 3 setup: first batch sealed for real", batch_a is not None)
        assert batch_a is not None
        log(f"batch_a.last_message_id = {batch_a.last_message_id}")

        # More events produced but deliberately never sealed.
        for i in range(3):
            await stream_adapter.produce(org_3, source_3, f"unsealed-{i}".encode())

        key_3 = f"kronos:stream:{org_3}:{source_3}"
        # Real XTRIM: evict everything except the last 1 entry -- past both
        # batch_a's watermark AND into the unsealed events.
        await redis.xtrim(key_3, maxlen=1, approximate=False)
        new_earliest = await stream_adapter.earliest_message_id(org_3, source_3)
        log(f"after real XTRIM MAXLEN=1, earliest retained message id = {new_earliest}")
        check(
            "real XTRIM moved the earliest retained id past batch_a's last_message_id",
            new_earliest is not None and _tuple(new_earliest) > _tuple(batch_a.last_message_id),
        )

        gap_raised = False
        try:
            await service_3.seal_pending(org_3, source_3)
        except EvidenceLossDetectedError as exc:
            gap_raised = True
            log(f"seal_pending() correctly raised EvidenceLossDetectedError: {exc}")
        check("GATE failure-mode: real MAXLEN trim past watermark raises "
              "EvidenceLossDetectedError (pages, not a warning)", gap_raised)

        async with engine.connect() as conn:
            gap_audit = (
                await conn.execute(
                    sa_text(
                        "SELECT event_type, details FROM audit_log WHERE org_id = :o "
                        "AND event_type = :t ORDER BY sequence_number DESC LIMIT 1"
                    ),
                    {"o": str(org_3), "t": AuditEventType.BATCH_SEAL_WATERMARK_GAP_DETECTED.value},
                )
            ).one_or_none()
        check("real BATCH_SEAL_WATERMARK_GAP_DETECTED audit event persisted in Postgres",
              gap_audit is not None)

    finally:
        server.shutdown()
        server.server_close()
        await redis.aclose()
        await engine.dispose()

    log("\n" + "=" * 78)
    failed = [label for label, ok in CHECKS if not ok]
    if failed:
        log(f"PoC FAILED -- {len(failed)}/{len(CHECKS)} checks failed:")
        for label in failed:
            log(f"  - {label}")
        log("GATE: NOT PASSED")
        return 1
    log(f"PoC PASSED -- all {len(CHECKS)} checks passed against real Redis/MinIO/Postgres/TSA.")
    log("GATE: PASSED -- real inclusion proof for an arbitrary sealed event verified "
        "true (and tampered variants verified false) from a freshly-refetched real "
        "Postgres row; both failure-mode requirements (never-ack-on-failure, "
        "page-on-unsealed-trim) demonstrated against real dependencies.")
    log("=" * 78)
    return 0


def _tuple(message_id: str) -> tuple[int, int]:
    ms, _, seq = message_id.partition("-")
    return int(ms), int(seq or 0)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
