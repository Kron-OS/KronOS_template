#!/usr/bin/env python3
"""Verification-first PoC: StreamNormalizationService against real Redis,
Postgres, MinIO, a real openssl-ts TSA, and real OpenSearch (roadmap M3/D4).

Pinned versions (read from this repo / this host, not assumed):
  - Redis server: real running `docker-redis-1` (redis:7-alpine), 7.4.9.
  - Postgres: real running `docker-postgres-1` (postgres:16-alpine), 16.14.
  - MinIO: real running `docker-minio-1` (minio/minio:latest).
  - OpenSearch: real running `docker-opensearch-1`
    (opensearchproject/opensearch:2.11.1), https://localhost:9200, admin/admin
    (confirmed via a real `curl -k -u admin:admin
    https://localhost:9200/_cluster/health` -> 200 before this PoC was
    written).
  - RFC 3161 TSA: same real openssl-ts-backed substitute as poc/rfc3161/ and
    poc/batch_sealing/ (the dev-compose `tsa` stub returns an empty body,
    confirmed in poc/rfc3161/README.md -- not a real ASN.1 responder).
  - Zeek conn.log field reference: independently re-verified against Zeek's
    own source (raw.githubusercontent.com/zeek/zeek,
    scripts/base/protocols/conn/main.zeek's Conn::Info record) immediately
    before writing this PoC -- ts:time, duration:interval (both
    JSON-serialized as fractional-second Unix epoch floats by Zeek's own
    JSON writer), proto:transport_proto, orig_bytes/resp_bytes:count. Matches
    src/application/stream_source_registry.py's ZeekConnLogNormalizer.

This script drives the real, unmodified production pipeline end to end:
  RedisStreamIngestAdapter (D1) -> BatchSealingService (D3) -> a real
  SealedBatch persisted in Postgres + a real WORM manifest in MinIO -> real
  StreamNormalizationService (D4) -> real OpenSearchClient bulk_index -> a
  real GET .../_search against docker-opensearch-1, independently confirming
  the resulting documents have correct ECS field names AND correct
  kronos.* StreamProvenance fields (source_id, batch_id, event_offset).

Run: ~/venv/bin/python3 poc/stream_normalization/run_poc.py
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
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from redis.asyncio import Redis as AsyncRedis  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_sealed_batch import PostgresSealedBatchRepository  # noqa: E402
from src.adapter.storage.sealed_batch_storage import S3SealedBatchStorage  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.batch_sealing import BatchSealingService  # noqa: E402
from src.application.sealing_trigger_policy import SizeBoundTriggerPolicy  # noqa: E402
from src.application.stream_normalization import StreamNormalizationService  # noqa: E402
from src.application.stream_source_registry import get_default_stream_normalizer_registry  # noqa: E402
from src.application.timeline_ingest import TimelineIngestionService  # noqa: E402
from src.application.timeline_normalization import build_stream_index_name  # noqa: E402
from src.application.timestamping import RFC3161TimestampService  # noqa: E402

REDIS_DSN = "redis://localhost:6379/3"
DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
MINIO_ENDPOINT = "http://localhost:9000"
MINIO_ACCESS_KEY = "kronos_minio"
MINIO_SECRET_KEY = "kronos_minio_dev_password"

TSA_HOST = "127.0.0.1"
TSA_PORT = 20320  # distinct from poc/rfc3161 (20318) and poc/batch_sealing (20319)

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
    """Identical technique to poc/rfc3161 and poc/batch_sealing's own helper."""
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


# Realistic Zeek default-JSON conn.log lines -- field names/shapes
# independently re-confirmed against Zeek's own Conn::Info record source
# immediately before writing this PoC (see module docstring).
_ZEEK_EVENTS = [
    {
        "ts": 1735689600.0 + i,
        "uid": f"C{i:016x}",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 50000 + i,
        "id.resp_h": "93.184.216.34",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 1.5 + i * 0.25,
        "orig_bytes": 512 + i * 10,
        "resp_bytes": 4096 + i * 20,
        "conn_state": "SF",
        "history": "ShADadFf",
        "orig_pkts": 6,
        "resp_pkts": 5,
    }
    for i in range(4)
]


async def main() -> int:
    log("=" * 78)
    log("PoC: StreamNormalizationService <-> real Redis/MinIO/Postgres/TSA/OpenSearch")
    log("=" * 78)
    if shutil.which("openssl") is None:
        log("FATAL: openssl binary not found on PATH")
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="kronos_poc_stream_norm_"))
    tsa_cnf = build_throwaway_tsa(workdir)
    handler = make_handler(tsa_cnf, workdir)
    server = socketserver.ThreadingTCPServer((TSA_HOST, TSA_PORT), handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    log(f"Real local TSA responder listening on http://{TSA_HOST}:{TSA_PORT}")

    redis = AsyncRedis.from_url(REDIS_DSN)
    engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
    await PostgresSealedBatchRepository.create_tables(engine)

    stream_adapter = RedisStreamIngestAdapter(redis)
    sealed_batch_repo = PostgresSealedBatchRepository(engine)
    audit_repo = PostgresAuditLogRepository(engine)
    audit_log = AuditLogService(audit_repo)
    tsa_service = RFC3161TimestampService(tsa_url=f"http://{TSA_HOST}:{TSA_PORT}/")
    storage = S3SealedBatchStorage(
        endpoint_url=MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        bucket_prefix="kronos-poc-stream-norm",
        retention_days=1,
    )
    opensearch = OpenSearchClient(
        hosts=[{"host": "localhost", "port": 9200}],
        http_auth=("admin", "admin"),
        use_ssl=True,
        verify_certs=False,
    )

    try:
        # -----------------------------------------------------------------
        # Step 1: seal a REAL batch of real Zeek-conn-log-shaped JSON events
        # -----------------------------------------------------------------
        org_id = uuid.uuid4()
        org_alias = "poc-stream-norm-org"
        source_id = "zeek-conn-log"

        sealing_service = BatchSealingService(
            stream_adapter, storage, tsa_service, audit_log, sealed_batch_repo,
            SizeBoundTriggerPolicy(max_events=len(_ZEEK_EVENTS)),
            consumer_name="poc-normalization-sealer",
        )
        for event in _ZEEK_EVENTS:
            await stream_adapter.produce(org_id, source_id, json.dumps(event).encode())
        log(f"Produced {len(_ZEEK_EVENTS)} real Zeek conn.log-shaped events onto "
            f"kronos:stream:{org_id}:{source_id}")

        sealed = await sealing_service.seal_pending(org_id, source_id)
        check("real batch sealed for real Zeek events", sealed is not None)
        assert sealed is not None
        log(f"Sealed batch_id={sealed.batch_id} event_count={sealed.event_count}")

        # -----------------------------------------------------------------
        # Step 2: normalize + index the REAL sealed batch via the real
        # StreamNormalizationService (D4) -- the actual component under test
        # -----------------------------------------------------------------
        ingestion = TimelineIngestionService(opensearch=opensearch, audit_log=audit_log)
        normalizer_registry = get_default_stream_normalizer_registry()
        normalization_service = StreamNormalizationService(
            sealed_batch_repo, storage, ingestion, normalizer_registry
        )

        indexed_count = await normalization_service.normalize_batch(
            org_id, sealed.batch_id, org_alias=org_alias
        )
        check("normalize_batch() indexed all 4 events", indexed_count == len(_ZEEK_EVENTS))
        log(f"StreamNormalizationService.normalize_batch() indexed {indexed_count} documents")

        # -----------------------------------------------------------------
        # Step 3: independently confirm via a REAL OpenSearch query -- not
        # just the return value -- that the documents have the correct ECS
        # field names and the correct kronos.* StreamProvenance fields.
        # -----------------------------------------------------------------
        index_name = build_stream_index_name(org_alias, source_id, _first_ts())
        await asyncio.sleep(1.5)  # real OpenSearch refresh interval, not assumed instantaneous
        import httpx

        async with httpx.AsyncClient(verify=False) as client:  # noqa: S501 -- dev-stack self-signed cert
            resp = await client.post(
                f"https://localhost:9200/{index_name}/_search",
                auth=("admin", "admin"),
                json={"query": {"match_all": {}}, "size": 10, "sort": [{"kronos.event_offset": "asc"}]},
            )
        log(f"\n--- real GET {index_name}/_search response (status={resp.status_code}) ---")
        log(json.dumps(resp.json(), indent=2)[:4000])

        check("real OpenSearch _search returned 200", resp.status_code == 200)
        body = resp.json()
        hits = body.get("hits", {}).get("hits", [])
        check("real OpenSearch index contains exactly 4 documents", len(hits) == 4)

        sources = [h["_source"] for h in hits]
        first = sources[0]
        check("real document has @timestamp (ECS core field)", "@timestamp" in first)
        check("real document has source.ip == 10.0.0.5 (ECS network field)",
              first.get("source", {}).get("ip") == "10.0.0.5")
        check("real document has network.transport == tcp",
              first.get("network", {}).get("transport") == "tcp")
        check("real document has network.protocol == ssl",
              first.get("network", {}).get("protocol") == "ssl")
        check("real document's event.duration is nanoseconds (1.5s -> 1_500_000_000)",
              first.get("event", {}).get("duration") == 1_500_000_000)

        kronos = first.get("kronos", {})
        check("real document's kronos.source_id == zeek-conn-log", kronos.get("source_id") == source_id)
        check("real document's kronos.batch_id matches the real sealed batch_id",
              kronos.get("batch_id") == str(sealed.batch_id))
        check("real document's kronos.org_id matches the real org_id",
              kronos.get("org_id") == str(org_id))
        check("real document's kronos.event_offset == 0 for the first sorted hit",
              kronos.get("event_offset") == 0)
        check("real document's kronos.case_id is absent (stream events are un-triaged at ingest)",
              "case_id" not in kronos)

        offsets = [h["_source"]["kronos"]["event_offset"] for h in hits]
        check("real documents' event_offsets are exactly [0,1,2,3], one per sealed event",
              offsets == [0, 1, 2, 3])

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
    log(f"PoC PASSED -- all {len(CHECKS)} checks passed against real Redis/MinIO/Postgres/TSA/OpenSearch.")
    log("=" * 78)
    return 0


def _first_ts():  # noqa: ANN202
    from datetime import UTC, datetime

    return datetime.fromtimestamp(_ZEEK_EVENTS[0]["ts"], tz=UTC)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
