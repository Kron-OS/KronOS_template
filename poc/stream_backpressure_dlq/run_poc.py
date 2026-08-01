#!/usr/bin/env python3
"""Verification-first PoC: D5 backpressure/DLQ/observability primitives
against the real dev stack (roadmap M3/D5).

Pinned versions (read from this repo / this host, not assumed -- matches
poc/stream_ingest_redis/, poc/batch_sealing/, poc/stream_normalization/):
  - Redis server: real running `docker-redis-1` (redis:7-alpine); confirmed
    7.4.9 live via `redis.asyncio.Redis.info()["redis_version"]` at the top
    of main() below (not assumed from a prior PoC's own note).
  - Postgres: real running `docker-postgres-1` (postgres:16-alpine).
  - MinIO: real running `docker-minio-1` (minio/minio:latest).
  - OpenSearch: real running `docker-opensearch-1`
    (opensearchproject/opensearch:2.11.1), https://localhost:9200,
    admin/admin.
  - RFC 3161 TSA: same real openssl-ts-backed substitute as poc/rfc3161/,
    poc/batch_sealing/, poc/stream_normalization/ (the dev-compose `tsa`
    service is a non-functional empty-body stub, per poc/rfc3161/README.md).

Three real scenarios, each against the real dev stack, no mocks:

(a) DLQ: seal a real batch of 5 Zeek-conn-log-shaped events where ONE is
    deliberately malformed (not valid JSON). Normalize via the real,
    modified StreamNormalizationService (roadmap M3/D5's actual bug fix)
    with a real PostgresDeadLetterSink. Confirm via an independent real
    Postgres SELECT (not the in-process return value) that exactly the bad
    event landed in dead_letter_events, and via an independent real
    OpenSearch _search that exactly the 4 good events were indexed.

(b) Consumer-group lag/health: produce 5 real events onto a fresh Redis
    stream, consume 3 without acking via a real consumer group, then call
    the real RedisStreamIngestAdapter.consumer_group_health() and
    cross-check its answer against RAW XPENDING/XINFO GROUPS calls made
    independently in this script (not trusting the adapter's own parsing).

(c) Sealer fall-behind alert: XADD one real event with an explicitly old
    message id (1 hour old) onto a brand-new stream, run a real
    BatchSealingService.seal_pending() with stall_alert_after_seconds=60,
    and confirm via an independent real Postgres SELECT that a real
    SEALER_FALL_BEHIND_DETECTED audit row was written -- while the batch
    itself still got sealed in the very same call (proving the alert pages
    without blocking).

Run: ~/venv/bin/python3 poc/stream_backpressure_dlq/run_poc.py
"""

from __future__ import annotations

import asyncio
import http.server
import json
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from redis.asyncio import Redis as AsyncRedis  # noqa: E402
from sqlalchemy import text as sa_text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_dead_letter import PostgresDeadLetterSink  # noqa: E402
from src.adapter.repository.postgres_sealed_batch import PostgresSealedBatchRepository  # noqa: E402
from src.adapter.storage.sealed_batch_storage import S3SealedBatchStorage  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.batch_sealing import BatchSealingService  # noqa: E402
from src.application.sealing_trigger_policy import SizeBoundTriggerPolicy  # noqa: E402
from src.application.stream_normalization import StreamNormalizationService  # noqa: E402
from src.application.stream_source_registry import (  # noqa: E402
    get_default_stream_normalizer_registry,
)
from src.application.timeline_ingest import TimelineIngestionService  # noqa: E402
from src.application.timeline_normalization import build_stream_index_name  # noqa: E402
from src.application.timestamping import RFC3161TimestampService  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402

REDIS_DSN = "redis://localhost:6379/3"
DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
MINIO_ENDPOINT = "http://localhost:9000"
MINIO_ACCESS_KEY = "kronos_minio"
MINIO_SECRET_KEY = "kronos_minio_dev_password"

TSA_HOST = "127.0.0.1"
# Port distinct from poc/rfc3161 (20318), poc/batch_sealing (20319),
# poc/stream_normalization (20320).
TSA_PORT = 20321

CHECKS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}", flush=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def _run(*args: str) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True)  # noqa: S603
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed: {args}\nSTDOUT:{result.stdout}\nSTDERR:{result.stderr}"
        )
    return result


def build_throwaway_tsa(workdir: Path) -> Path:
    """Identical technique to poc/rfc3161, poc/batch_sealing, poc/stream_normalization."""
    ca_key, ca_pem = workdir / "ca.key", workdir / "ca.pem"
    tsa_key, tsa_csr, tsa_pem = workdir / "tsa.key", workdir / "tsa.csr", workdir / "tsa.pem"
    ext_cnf = workdir / "tsa_ext.cnf"
    ext_cnf.write_text("extendedKeyUsage=critical,timeStamping\n")

    _run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_pem),
        "-days",
        "2",
        "-nodes",
        "-subj",
        "/CN=Test CA",
    )
    _run(
        "openssl",
        "req",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(tsa_key),
        "-out",
        str(tsa_csr),
        "-nodes",
        "-subj",
        "/CN=Test TSA",
    )
    _run(
        "openssl",
        "x509",
        "-req",
        "-in",
        str(tsa_csr),
        "-CA",
        str(ca_pem),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(tsa_pem),
        "-days",
        "2",
        "-extfile",
        str(ext_cnf),
    )

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
                [
                    "openssl",
                    "ts",
                    "-reply",
                    "-config",
                    str(tsa_cnf),
                    "-queryfile",
                    req_path,
                    "-out",
                    resp_path,
                ],
                capture_output=True,
                text=True,
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


def _zeek_event(i: int) -> bytes:
    return json.dumps(
        {
            "ts": 1735689600.0 + i,
            "id.orig_h": "10.0.0.5",
            "id.orig_p": 50000 + i,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 443,
            "proto": "tcp",
        }
    ).encode()


async def main() -> int:  # noqa: PLR0915
    log("=" * 78)
    log("PoC: D5 backpressure/DLQ/observability <-> real Redis/Postgres/MinIO/TSA/OpenSearch")
    log("=" * 78)
    if shutil.which("openssl") is None:
        log("FATAL: openssl binary not found on PATH")
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="kronos_poc_d5_"))
    tsa_cnf = build_throwaway_tsa(workdir)
    handler = make_handler(tsa_cnf, workdir)
    # allow_reuse_address: socketserver's own default is False, so a rapid
    # repeated run of this PoC (this script's own TCP server, not the real
    # dev-stack services) can otherwise hit a real but uninteresting
    # EADDRINUSE from the previous run's socket sitting in TIME_WAIT.
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer((TSA_HOST, TSA_PORT), handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    log(f"Real local TSA responder listening on http://{TSA_HOST}:{TSA_PORT}")

    redis = AsyncRedis.from_url(REDIS_DSN)
    redis_info = await redis.info("server")
    log(
        f"Real Redis server version: {redis_info.get('redis_version')} "
        f"(pinned expectation: 7.x, matches poc/stream_ingest_redis/'s own 7.4.9 finding)"
    )

    engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
    await PostgresAuditLogRepository.create_tables(engine)
    await PostgresSealedBatchRepository.create_tables(engine)
    await PostgresDeadLetterSink.create_tables(engine)

    stream_adapter = RedisStreamIngestAdapter(redis)
    sealed_batch_repo = PostgresSealedBatchRepository(engine)
    audit_repo = PostgresAuditLogRepository(engine)
    audit_log = AuditLogService(audit_repo)
    dead_letter_sink = PostgresDeadLetterSink(engine)
    tsa_service = RFC3161TimestampService(tsa_url=f"http://{TSA_HOST}:{TSA_PORT}/")
    storage = S3SealedBatchStorage(
        endpoint_url=MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        bucket_prefix="kronos-poc-d5",
        retention_days=1,
    )
    opensearch = OpenSearchClient(
        hosts=[{"host": "localhost", "port": 9200}],
        http_auth=("admin", "admin"),
        use_ssl=True,
        verify_certs=False,
    )

    try:
        # ===================================================================
        # SCENARIO (a): dead-letter one malformed event, index the rest
        # ===================================================================
        log("\n" + "=" * 78)
        log("SCENARIO (a): one malformed event in a batch of 5 -- DLQ, not data loss")
        log("=" * 78)

        org_a = uuid.uuid4()
        org_alias_a = "poc-d5-dlq-org"
        source_a = "zeek-conn-log"

        events_a = [
            _zeek_event(0),
            _zeek_event(1),
            b"{{{ not valid json at all",
            _zeek_event(3),
            _zeek_event(4),
        ]
        sealing_service_a = BatchSealingService(
            stream_adapter,
            storage,
            tsa_service,
            audit_log,
            sealed_batch_repo,
            SizeBoundTriggerPolicy(max_events=len(events_a)),
            consumer_name="poc-d5-dlq-sealer",
        )
        for payload in events_a:
            await stream_adapter.produce(org_a, source_a, payload)
        log(
            f"Produced {len(events_a)} real events (1 deliberately malformed at offset 2) "
            f"onto kronos:stream:{org_a}:{source_a}"
        )

        sealed_a = await sealing_service_a.seal_pending(org_a, source_a)
        check(
            "real batch sealed despite containing one malformed event "
            "(sealing hashes raw bytes -- it doesn't parse/validate content)",
            sealed_a is not None,
        )
        assert sealed_a is not None

        ingestion = TimelineIngestionService(opensearch=opensearch, audit_log=audit_log)
        normalizer_registry = get_default_stream_normalizer_registry()
        normalization_service = StreamNormalizationService(
            sealed_batch_repo,
            storage,
            ingestion,
            normalizer_registry,
            dead_letter_sink,
            audit_log,
        )

        result_a = await normalization_service.normalize_batch(
            org_a, sealed_a.batch_id, org_alias=org_alias_a
        )
        log(
            f"normalize_batch() -> indexed_count={result_a.indexed_count} "
            f"dead_lettered_count={result_a.dead_lettered_count}"
        )
        check(
            "exactly 4 good events indexed (not fewer -- the bad one did NOT abort the rest)",
            result_a.indexed_count == 4,
        )
        check(
            "exactly 1 event dead-lettered (not silently dropped/conflated)",
            result_a.dead_lettered_count == 1,
        )

        # Independent real Postgres SELECT -- a separate round trip from the
        # in-process PostgresDeadLetterSink object used above.
        async with engine.connect() as conn:
            dl_rows = (
                await conn.execute(
                    sa_text(
                        "SELECT event_offset, payload, error_type FROM dead_letter_events "
                        "WHERE org_id = :o AND batch_id = :b"
                    ),
                    {"o": str(org_a), "b": str(sealed_a.batch_id)},
                )
            ).all()
        check(
            "real Postgres dead_letter_events has exactly 1 row for this batch", len(dl_rows) == 1
        )
        if dl_rows:
            check("real dead-lettered row is the correct offset (2)", dl_rows[0][0] == 2)
            check(
                "real dead-lettered row's payload matches the original malformed bytes",
                bytes(dl_rows[0][1]) == events_a[2],
            )
            check(
                "real dead-lettered row has a real error_type (ParsingError)",
                dl_rows[0][2] == "ParsingError",
            )

        # Independent real Postgres SELECT for the audit event.
        async with engine.connect() as conn:
            dl_audit = (
                await conn.execute(
                    sa_text(
                        "SELECT event_type FROM audit_log WHERE org_id = :o " "AND event_type = :t"
                    ),
                    {"o": str(org_a), "t": AuditEventType.STREAM_EVENT_DEAD_LETTERED.value},
                )
            ).all()
        check("real STREAM_EVENT_DEAD_LETTERED audit row persisted in Postgres", len(dl_audit) == 1)

        # Independent real OpenSearch query -- exactly the 4 good events landed.
        index_name = build_stream_index_name(
            org_alias_a,
            source_a,
            __import__("datetime").datetime.fromtimestamp(
                1735689600.0, tz=__import__("datetime").UTC
            ),
        )
        await asyncio.sleep(1.5)
        import httpx

        async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
            resp = await client.post(
                f"https://localhost:9200/{index_name}/_search",
                auth=("admin", "admin"),
                # Filtered on THIS run's own real batch_id, not match_all --
                # this index is shared across repeated runs of this PoC
                # (fixed org_alias/fixed Zeek event timestamps -> same
                # index name every run), so match_all would double-count
                # documents left behind by a prior run.
                json={
                    "query": {"term": {"kronos.batch_id": str(sealed_a.batch_id)}},
                    "size": 10,
                },
            )
        check("real OpenSearch _search returned 200 for scenario (a)", resp.status_code == 200)
        hits_a = resp.json().get("hits", {}).get("hits", [])
        check(
            "real OpenSearch has exactly 4 documents for THIS run's batch_id (not 5, not 0)",
            len(hits_a) == 4,
        )
        offsets_a = sorted(h["_source"]["kronos"]["event_offset"] for h in hits_a)
        check(
            "real indexed offsets are exactly [0,1,3,4] -- offset 2 (bad) correctly absent",
            offsets_a == [0, 1, 3, 4],
        )

        # ===================================================================
        # SCENARIO (b): real consumer-group lag/health primitive
        # ===================================================================
        log("\n" + "=" * 78)
        log("SCENARIO (b): real consumer-group lag/health via XPENDING + XINFO GROUPS")
        log("=" * 78)

        org_b = uuid.uuid4()
        source_b = "poc-lag-source"
        group_b = "poc-lag-group"

        for i in range(5):
            await stream_adapter.produce(org_b, source_b, f"event-{i}".encode())
        await stream_adapter.ensure_consumer_group(org_b, source_b, group_b, start="0")
        consumed = await stream_adapter.consume(org_b, source_b, group_b, "poc-consumer-1", count=3)
        check(
            "real consume() delivered exactly 3 of the 5 real events (unacked)", len(consumed) == 3
        )

        health = await stream_adapter.consumer_group_health(org_b, source_b, group_b)
        log(
            f"consumer_group_health() -> pending_count={health.pending_count} "
            f"lag={health.lag} consumers={health.consumer_pending_counts}"
        )
        check(
            "real ConsumerGroupHealth.pending_count == 3 (delivered, unacked)",
            health.pending_count == 3,
        )
        check(
            "real ConsumerGroupHealth.lag == 2 (never delivered to any consumer)", health.lag == 2
        )
        check(
            "real ConsumerGroupHealth.consumer_pending_counts attributes all 3 to poc-consumer-1",
            health.consumer_pending_counts == {"poc-consumer-1": 3},
        )

        # Cross-check against RAW XPENDING/XINFO GROUPS calls, independent of
        # the adapter's own parsing -- not trusting consumer_group_health()'s
        # own return value alone.
        raw_key = f"kronos:stream:{org_b}:{source_b}"
        raw_pending = await redis.xpending(raw_key, group_b)
        raw_groups = await redis.xinfo_groups(raw_key)
        raw_lag = next(g["lag"] for g in raw_groups if g["name"] == group_b.encode())
        log(f"raw XPENDING: {raw_pending}")
        log(f"raw XINFO GROUPS: {raw_groups}")
        check(
            "raw XPENDING pending count matches adapter's own answer",
            raw_pending["pending"] == health.pending_count,
        )
        check("raw XINFO GROUPS lag matches adapter's own answer", raw_lag == health.lag)

        # Now ack the 3 pending and consume the remaining 2 -- lag and
        # pending must both go to zero for real.
        await stream_adapter.ack(org_b, source_b, group_b, *[m.message_id for m in consumed])
        remaining = await stream_adapter.consume(
            org_b, source_b, group_b, "poc-consumer-1", count=10
        )
        await stream_adapter.ack(org_b, source_b, group_b, *[m.message_id for m in remaining])
        health_after = await stream_adapter.consumer_group_health(org_b, source_b, group_b)
        check("after acking everything, real pending_count == 0", health_after.pending_count == 0)
        check("after consuming everything, real lag == 0", health_after.lag == 0)

        # Health for a group that was never created -- lag=None, not 0.
        health_missing = await stream_adapter.consumer_group_health(
            org_b, source_b, "never-existed"
        )
        check(
            "consumer_group_health() for a nonexistent group returns lag=None, not 0",
            health_missing.lag is None and health_missing.pending_count == 0,
        )

        # ===================================================================
        # SCENARIO (c): sealer fall-behind alert fires under a real induced
        # "sealer hasn't run in too long" condition, without blocking sealing
        # ===================================================================
        log("\n" + "=" * 78)
        log("SCENARIO (c): real sealer fall-behind alert -- pages, does not block sealing")
        log("=" * 78)

        org_c = uuid.uuid4()
        source_c = "poc-fallbehind-source"
        raw_key_c = f"kronos:stream:{org_c}:{source_c}"
        one_hour_ago_ms = int(time.time() * 1000) - 3600 * 1000
        old_message_id = f"{one_hour_ago_ms}-1"
        await redis.xadd(raw_key_c, {b"payload": b"a-real-stale-event"}, id=old_message_id)
        log(
            f"XADD'd one real event with an explicitly 1-hour-old id ({old_message_id}) "
            f"onto a brand-new stream {raw_key_c}"
        )

        sealing_service_c = BatchSealingService(
            stream_adapter,
            storage,
            tsa_service,
            audit_log,
            sealed_batch_repo,
            SizeBoundTriggerPolicy(max_events=1),
            consumer_name="poc-d5-fallbehind-sealer",
            stall_alert_after_seconds=60.0,  # 1 minute -- far below the real 1-hour age
        )
        sealed_c = await sealing_service_c.seal_pending(org_c, source_c)
        check(
            "the stale segment was still sealed in the SAME call the alert fired in "
            "(pages, does not block)",
            sealed_c is not None,
        )

        async with engine.connect() as conn:
            alert_rows = (
                await conn.execute(
                    sa_text(
                        "SELECT event_type, details FROM audit_log WHERE org_id = :o "
                        "AND event_type = :t"
                    ),
                    {"o": str(org_c), "t": AuditEventType.SEALER_FALL_BEHIND_DETECTED.value},
                )
            ).all()
        check(
            "real SEALER_FALL_BEHIND_DETECTED audit row persisted in Postgres", len(alert_rows) == 1
        )
        if alert_rows:
            details = alert_rows[0][1]
            details = json.loads(details) if isinstance(details, str) else details
            check(
                "real alert's oldest_pending_age_seconds reflects the real ~3600s age",
                details.get("oldest_pending_age_seconds", 0) >= 3599,
            )

        async with engine.connect() as conn:
            sealed_rows = (
                await conn.execute(
                    sa_text(
                        "SELECT event_type FROM audit_log WHERE org_id = :o AND event_type = :t"
                    ),
                    {"o": str(org_c), "t": AuditEventType.BATCH_SEALED.value},
                )
            ).all()
        check(
            "real BATCH_SEALED audit row ALSO persisted -- the alert is additive, not a block",
            len(sealed_rows) == 1,
        )

    finally:
        server.shutdown()
        server.server_close()
        await redis.aclose()
        await engine.dispose()
        await opensearch._client.close()

    log("\n" + "=" * 78)
    failed = [label for label, ok in CHECKS if not ok]
    if failed:
        log(f"PoC FAILED -- {len(failed)}/{len(CHECKS)} checks failed:")
        for label in failed:
            log(f"  - {label}")
        return 1
    log(
        f"PoC PASSED -- all {len(CHECKS)} checks passed against real "
        "Redis/Postgres/MinIO/TSA/OpenSearch."
    )
    log("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
