#!/usr/bin/env python3
"""PoC: the autonomous detection pipeline actually runs on a real Celery
beat schedule, with no human calling seal_pending()/normalize_batch()/
sync_org_findings() by hand at any point after the initial real event lands
(roadmap Milestone W/W1, closes docs/ASSESSMENT_SYNTHESIS_2026-08.md's
P0-W1 -- the incident-response walkthrough's F1/F2/F3).

## What this is NOT

This is explicitly NOT a re-proof that the underlying chain (seal -> index
-> SA monitor -> sync -> Detection) works mechanically -- that was already
proven, manually, 35/35 checks, in poc/l3_chain_collector_to_detect/. This
PoC's whole job is the one thing that PoC's own "Explicitly flagged, not
yet done" section named as still open: "nothing schedules seal_pending()/
normalize_batch()/sync_org_findings() automatically in production yet (no
beat task) -- this PoC drives each stage manually, proving the mechanism,
not automatic invocation." That gap is what W1's real `src/` changes
(celery_app.py's three new tasks + celery_streaming.py) close, and this
script is the real, live proof they actually fire on schedule.

Consequently this script also does NOT stand up a real mTLS collector
listener (poc/collector_ingest_mtls/, poc/l3_chain_collector_to_detect/
already proved that hop for real) -- it produces directly onto the real
Redis stream via the same real `StreamIngestAdapter.produce()` the mTLS
route itself calls after authentication, which is the actually-relevant
real transport primitive `seal_pending_streams`' own discovery
(`list_active_streams()`) reads from.

## Versions (pinned, read from this repo/host, matching every prior PoC)

- Redis: `docker-redis-1` (`redis:7-alpine`), stream DB 3, Celery broker
  DB 1, Celery result backend DB 2 (real docker-compose.dev.yml values).
- Postgres: `docker-postgres-1` (`postgres:16-alpine`).
- MinIO: `docker-minio-1` (`minio/minio:latest`).
- OpenSearch: `docker-opensearch-1` (`opensearchproject/opensearch:2.11.1`).
- Keycloak: `docker-keycloak-1` (`quay.io/keycloak/keycloak:26.2`) -- a
  REAL (not synthetic) org, created fresh for this run via the real Admin
  REST API (`raw_create_org`/`raw_delete_org` below, mirrored from
  `poc/containment_approval_gate/run_poc.py`'s own proven technique) and
  deleted again at teardown -- required because `sync_detection_findings`'s
  own real org-discovery (`KeycloakAdminClient.list_organizations()`) only
  ever finds REAL Keycloak orgs, not a synthetic uuid the way `poc/l3_chain_
  collector_to_detect/` was free to use for its own manually-driven
  `TenantContext`. An earlier version of this script reused the one
  pre-existing `kronos-dev` org (`id=482072f5-8086-4815-be03-879cc2eaecb5`)
  instead of creating a fresh one; that collided with real, pre-existing
  `sealed_batches` history for that org combined with the required literal
  `source_id` (see the `source_id`/`org_alias` assignment below for the
  full, live-confirmed root cause) -- a fresh org is what actually fixes it,
  not just documentation.
- RFC 3161 TSA: same real openssl-`ts`-backed local substitute every prior
  PoC in this chain uses (the dev-compose `tsa` stub is non-functional).
- Celery: real, unmodified `src.external.celery_app.celery_app` (via the
  `_beat_schedule_override.py` wrapper in this same directory -- see that
  file's own docstring for exactly what it does and does not change).

## The real autonomy proof this script captures

1. Starts a REAL, throwaway `celery worker` + `celery beat` process pair
   (subprocess, not in-process/eager) against the real dev-stack broker,
   BEFORE any real telemetry exists -- so beat is already ticking on an
   empty backlog when data lands.
2. Produces real events directly onto the real Redis stream.
3. From this point on, NEVER calls `seal_pending()`/`normalize_batch()`/
   `sync_org_findings()` itself -- only POLLS real Postgres/OpenSearch
   state and records the real wall-clock timestamp each expected side
   effect first appears, proving the real beat schedule -- not this
   script -- did the work.
4. Exercises the new `POST /api/detections/{id}/sync-to-siem/{sink}` route
   (roadmap W1 item (d)) against the REAL Detection row the autonomous
   pipeline itself just created in step 3 -- tying all four sub-items
   together in one real, coherent run.

Run: ~/venv/bin/python3 poc/autonomous_detection_pipeline/run_poc.py
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from redis.asyncio import Redis as AsyncRedis  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.integration_sink.sink_authenticator import StaticTokenAuthenticator  # noqa: E402
from src.adapter.integration_sink.splunk_hec_sink import SplunkHecSink  # noqa: E402
from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.adapter.repository.postgres_sealed_batch import PostgresSealedBatchRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.detection_sink_push import DetectionSinkPushService  # noqa: E402
from src.application.playbook import PlaybookActionRegistry  # noqa: E402
from src.application.playbook_execution import PlaybookExecutionService  # noqa: E402
from src.application.splunk_detection_mapper import SplunkDetectionMapper  # noqa: E402
from src.application.sync_detection_to_siem_action import SyncDetectionToSiemAction  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.external.dependencies import (  # noqa: E402
    get_detection_repository,
    get_playbook_action_registry,
    get_playbook_execution_service,
)
from src.external.fastapi_app import create_app  # noqa: E402
from src.external.middleware.tenant_context import get_tenant_context  # noqa: E402

REDIS_DSN = "redis://localhost:6379/3"
DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
OS_URL = "https://localhost:9200"
OS_ADMIN = ("admin", "admin")
KEYCLOAK_URL = "http://localhost:8080"

TSA_HOST = "127.0.0.1"
TSA_PORT = 20330  # distinct from every other PoC's own local TSA port in this chain

# CORRECTION (this fix): a prior version of this script hardcoded the one
# pre-existing dev-realm org (kronos-dev, id=482072f5-8086-4815-be03-
# 879cc2eaecb5) here, reasoning that sync_detection_findings's own real
# org-discovery (list_organizations()) only ever finds REAL Keycloak orgs so
# a synthetic uuid (poc/l3_chain_collector_to_detect/'s own approach) would
# not work. That reasoning about org-discovery is still correct, but reusing
# THIS SPECIFIC pre-existing org combined with the source_id below (which
# itself must stay a real, exact literal -- see its own comment) collided
# with real, pre-existing `sealed_batches` history for that literal
# (org_id, source_id) pair: a real BatchSealingService.EvidenceLossDetectedError
# every single run, confirmed live (`SELECT ... FROM sealed_batches WHERE
# org_id='482072f5-...' AND source_id='zeek-conn-log'` returned real rows
# sealed 2026-08-08, watermark last_message_id=1786162470729-0, while any
# fresh production onto the stream today necessarily gets a newer,
# higher Redis stream id -- `_check_watermark_gap` correctly treats that as
# unrecoverable evidence loss and refuses to seal, by design, with no admin
# recovery path in `src/` today). Renaming/randomizing source_id instead
# (this script's own even-earlier attempt) was already tried and reverted --
# see that constant's own comment for why it breaks normalization instead.
# The two constraints (source_id must be the real literal; (org_id,
# source_id) must have zero prior sealed_batches history) are jointly only
# satisfiable by using a FRESH org_id, so this fix creates one for real, the
# same proven, real Admin API technique poc/containment_approval_gate/
# run_poc.py and poc/global_l4_e2e/run_poc.py already use for their own
# ephemeral per-run orgs (raw_create_org/raw_delete_org below, mirrored from
# poc/containment_approval_gate/run_poc.py almost verbatim) -- list_
# organizations() finds ANY real Keycloak org, not specifically kronos-dev,
# so a genuinely fresh org satisfies its own discovery requirement too.
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"
KEYCLOAK_REALM = "kronos"

TARGET_RULE_ID = "1fc0809e-06bf-4de3-ad52-25e5263b7623"
TARGET_RULE_TAG = "attack.t1021.001"

CHECKS: list[tuple[str, bool]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((label, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""), flush=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def _run(*args: str) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True)  # noqa: S603
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed: {args}\nSTDOUT:{result.stdout}\nSTDERR:{result.stderr}"
        )
    return result


# ---------------------------------------------------------------------------
# Real Keycloak Admin API helpers for a fresh, ephemeral per-run org --
# mirrored from poc/containment_approval_gate/run_poc.py's own proven
# raw_create_org/raw_delete_org (raw httpx, deliberately NOT the src/
# adapter under test, so this bootstrap step stays independent of it).
# ---------------------------------------------------------------------------


async def get_raw_admin_token(client: httpx.AsyncClient) -> str:
    resp = await client.post(
        f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": KEYCLOAK_ADMIN_CLIENT_ID,
            "client_secret": KEYCLOAK_ADMIN_CLIENT_SECRET,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


async def raw_get_org_id(client: httpx.AsyncClient, token: str, alias: str) -> str:
    resp = await client.get(
        f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/organizations?first=0&max=1000",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    for org in resp.json():
        if org["alias"] == alias:
            return org["id"]
    raise RuntimeError(f"org alias {alias} not found")


async def raw_create_org(client: httpx.AsyncClient, token: str, alias: str, name: str) -> str:
    # Real finding (Keycloak 26.2.5, re-confirmed live for this fix, same as
    # poc/containment_approval_gate/'s own prior finding): organization
    # creation rejects an empty domains list with a real 400 ("You must
    # provide at least one domain") -- a real, verified, non-clashing
    # PoC-only domain is required. "name" must also be unique, not just
    # "alias" (a second run whose org survived a crash before cleanup got a
    # real 409 Conflict reusing a hardcoded name) -- both are suffixed with
    # the same run-unique token below.
    resp = await client.post(
        f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/organizations",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": name,
            "alias": alias,
            "enabled": True,
            "domains": [{"name": f"{alias}.invalid", "verified": True}],
        },
    )
    resp.raise_for_status()
    return await raw_get_org_id(client, token, alias)


async def raw_delete_org(client: httpx.AsyncClient, token: str, org_id: str) -> None:
    resp = await client.delete(
        f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/organizations/{org_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code not in (204, 404):
        raise RuntimeError(f"failed to delete PoC org {org_id}: {resp.status_code} {resp.text}")


def benign_event(seq: int) -> dict:
    return {
        "ts": time.time(),
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 51000 + seq,
        "id.resp_h": "10.0.0.10",
        "id.resp_p": 443,
        "proto": "tcp",
        "conn_state": "SF",
    }


def malicious_rdp_event(public_source_ip: str) -> dict:
    return {
        "ts": time.time(),
        "id.orig_h": public_source_ip,
        "id.orig_p": 51234,
        "id.resp_h": "10.0.0.10",
        "id.resp_p": 3389,
        "proto": "tcp",
        "conn_state": "SF",
    }


# ---------------------------------------------------------------------------
# Throwaway RFC 3161 TSA responder (identical technique to every prior PoC
# in this chain -- poc/l3_chain_collector_to_detect/ etc.)
# ---------------------------------------------------------------------------


def build_throwaway_tsa(workdir: Path) -> Path:
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


def make_tsa_handler(tsa_cnf: Path, workdir: Path):  # noqa: ANN201
    class Handler(BaseHTTPRequestHandler):
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


# ---------------------------------------------------------------------------
# Throwaway Splunk-HEC-protocol-accurate stand-in (identical technique to
# poc/integration_sink_splunk_hec/) -- used only for W1 item (d)'s own
# verification.
# ---------------------------------------------------------------------------

REAL_TOKEN = "poc-autonomous-pipeline-hec-token"  # nosec B105 -- local PoC-only stand-in value


class SplunkHecStandInHandler(BaseHTTPRequestHandler):
    received: list[dict] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        auth_header = self.headers.get("Authorization")
        if auth_header != f"Splunk {REAL_TOKEN}":
            self._send_json(403, {"text": "Invalid token", "code": 4})
            return
        try:
            event = json.loads(raw.decode())
        except json.JSONDecodeError:
            self._send_json(400, {"text": "Invalid data format", "code": 6})
            return
        SplunkHecStandInHandler.received.append(event)
        self._send_json(200, {"text": "Success", "code": 0})

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:  # noqa: A002
        pass


def start_http_server(handler: type) -> tuple[HTTPServer, threading.Thread, int]:
    server = HTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


async def main_async() -> int:  # noqa: C901, PLR0915
    if shutil.which("openssl") is None:
        log("FATAL: openssl binary not found on PATH")
        return 1
    # Same interpreter's own venv (not bare "celery" -- PATH may not include
    # the venv's bin/ dir when this script is invoked with a full python
    # binary path, e.g. ~/venv/bin/python3 poc/.../run_poc.py).
    celery_bin = str(Path(sys.executable).parent / "celery")
    if not Path(celery_bin).exists():
        log(f"FATAL: celery binary not found at {celery_bin}")
        return 1

    work_dir = Path(tempfile.mkdtemp(prefix="kronos_poc_autonomous_"))
    tsa_server: socketserver.ThreadingTCPServer | None = None
    worker_proc: subprocess.Popen | None = None
    beat_proc: subprocess.Popen | None = None
    hec_server: HTTPServer | None = None
    redis: AsyncRedis | None = None
    engine = None
    os_client: httpx.Client | None = None
    created_org_id: str | None = None

    # source_id MUST be this exact literal, not a per-run-randomized value:
    # the real normalizer registry (src/application/stream_source_registry.py
    # ::StreamSourceNormalizerRegistry) keys on this exact string --
    # ZeekConnLogNormalizer.source_id == "zeek-conn-log", confirmed by
    # direct read of that class's own docstring ("the registry keys on
    # this exact string ... A deployment running many physical collectors
    # of the same format under distinct per-host source_ids would need a
    # prefix or source-type-field lookup instead of this exact match --
    # flagged as follow-up, not needed for this pass's one concrete
    # source"). A randomized per-run source_id (this script's own first,
    # broken attempt) makes normalize_stream_batch fail forever with
    # "No stream normalizer registered" -- a real bug this run caught live
    # (see run's own first attempt, aborted after confirming the failure
    # in the real worker log).
    #
    # Run-to-run isolation instead comes from the ORG, not the source_id:
    # this script's own SECOND attempt kept source_id literal but reused the
    # one pre-existing real kronos-dev org (id=482072f5-...) -- see the old
    # REAL_ORG_ID/REAL_ORG_ALIAS comment above -- and that combination
    # collided with real, pre-existing sealed_batches history for exactly
    # that (org_id, source_id) pair, a real BatchSealingService.
    # EvidenceLossDetectedError every run (confirmed live via a direct
    # Postgres query before this fix: rows sealed 2026-08-08 for this exact
    # pair). A fresh, genuinely unique real Keycloak org (created below, via
    # the same proven raw_create_org/raw_delete_org technique poc/
    # containment_approval_gate/run_poc.py already uses) has zero prior
    # sealed_batches rows for ANY source_id, so this exact (org_id,
    # "zeek-conn-log") pair is guaranteed collision-free -- satisfying both
    # constraints at once: normalizer keeps its required literal, and the
    # sealing watermark starts genuinely empty.
    source_id = "zeek-conn-log"
    run_suffix = uuid.uuid4().hex[:8]
    org_alias = f"kronos-poc-w1-{run_suffix}"
    # Must exactly match the REAL production naming convention
    # (SecurityAnalyticsDetectorProvisioner._detector_name, detector_
    # provisioner.py:127-128: f"kronos-{org_alias}-{log_type}-detector",
    # log_type from get_default_log_types() == ("windows", "cloudtrail",
    # "network")) -- NOT source_id ("zeek-conn-log") and NOT a random
    # suffix. DetectionSyncService's real FindingsClient.fetch_org_findings
    # discovers findings by an exact `terms` match against
    # f"kronos-{org_alias}-{log_type}-detector" for each configured
    # log_type (findings_client.py:102) -- a source_id-based or
    # suffixed name is invisible to that query, so step 7's real,
    # autonomous sync would find the real finding (T_finding passes) but
    # NEVER create a Detection row for it (confirmed live: sync ran
    # every ~15s and returned 0 every cycle for 3+ minutes even after the
    # finding existed). org_alias is already run-unique (run_suffix
    # above), so no extra suffix is needed to avoid collisions.
    detector_name = f"kronos-{org_alias}-network-detector"

    try:
        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("-1. Real, fresh, ephemeral Keycloak org for this run only")
        print("=" * 78)
        async with httpx.AsyncClient(timeout=15) as raw:
            admin_token = await get_raw_admin_token(raw)
            created_org_id = await raw_create_org(
                raw, admin_token, org_alias, f"KronOS W1 PoC {run_suffix}"
            )
        org_id = uuid.UUID(created_org_id)
        log(f"real Keycloak org created: alias={org_alias} id={org_id}")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("0. Real local TSA responder + real throwaway Celery worker/beat")
        print("=" * 78)
        tsa_cnf = build_throwaway_tsa(work_dir)
        tsa_handler = make_tsa_handler(tsa_cnf, work_dir)
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        tsa_server = socketserver.ThreadingTCPServer((TSA_HOST, TSA_PORT), tsa_handler)
        threading.Thread(target=tsa_server.serve_forever, daemon=True).start()
        log(f"real local TSA responder listening on http://{TSA_HOST}:{TSA_PORT}")

        env = os.environ.copy()
        env.update(
            {
                "DATABASE_URL": DATABASE_URL,
                "REDIS_URL": "redis://localhost:6379/0",
                # Deliberately NOT the real docker-compose DB1/DB2 broker/
                # backend the already-running docker-celery-worker-1/
                # docker-celery-beat-1 containers share -- those containers
                # run the OLD image (built before this PoC's src/ changes)
                # and would either compete for or silently reject (unknown
                # task name) messages for the three new tasks under test.
                # DB4/DB5 give this throwaway worker/beat pair their own
                # real, private, but still-real Redis broker/backend on the
                # exact same real Redis instance -- isolates the process
                # pair, not the infrastructure under test.
                "CELERY_BROKER_URL": "redis://localhost:6379/4",
                "CELERY_RESULT_BACKEND": "redis://localhost:6379/5",
                "STREAM_REDIS_DB": "3",
                "MINIO_ENDPOINT": "localhost:9000",
                "MINIO_ACCESS_KEY": "kronos_minio",
                "MINIO_SECRET_KEY": "kronos_minio_dev_password",
                "MINIO_USE_TLS": "false",
                "OPENSEARCH_URL": OS_URL,
                "OPENSEARCH_USERNAME": "admin",
                "OPENSEARCH_PASSWORD": "admin",
                "OPENSEARCH_SECURITY_ENABLED": "false",
                "KEYCLOAK_URL": KEYCLOAK_URL,
                "KEYCLOAK_REALM": "kronos",
                "KEYCLOAK_CLIENT_ID": "kronos-backend",
                "KEYCLOAK_CLIENT_SECRET": "kronos-backend-secret",
                "TSA_URL": f"http://{TSA_HOST}:{TSA_PORT}/",
                # Required Settings fields this task set never touches --
                # dummy unreachable values are honest here, same precedent
                # poc/celery_beat/README.md already documents.
                "VAULT_URL": "http://127.0.0.1:1",
                "VAULT_TOKEN": "unused-in-this-poc",
                "JWT_ISSUER": f"{KEYCLOAK_URL}/realms/kronos",
            }
        )
        beat_schedule_file = str(work_dir / "celerybeat-schedule")
        worker_log = (work_dir / "worker.log").open("w")
        beat_log = (work_dir / "beat.log").open("w")
        poc_dir = str(Path(__file__).resolve().parent)
        env["PYTHONPATH"] = f"{poc_dir}:{REPO_ROOT}:{env.get('PYTHONPATH', '')}"

        worker_proc = subprocess.Popen(  # noqa: S603
            [
                celery_bin,
                "-A",
                "_beat_schedule_override",
                "worker",
                "-Q",
                "q.index",
                "-c",
                "4",
                "--loglevel=info",
            ],
            cwd=poc_dir,
            env=env,
            stdout=worker_log,
            stderr=subprocess.STDOUT,
        )
        beat_proc = subprocess.Popen(  # noqa: S603
            [
                celery_bin,
                "-A",
                "_beat_schedule_override",
                "beat",
                "--loglevel=info",
                f"--schedule={beat_schedule_file}",
            ],
            cwd=poc_dir,
            env=env,
            stdout=beat_log,
            stderr=subprocess.STDOUT,
        )
        log(f"real throwaway celery worker started: pid={worker_proc.pid} (log: {worker_log.name})")
        log(
            f"real throwaway celery beat started: pid={beat_proc.pid} (log: {beat_log.name}, "
            f"seal-pending-streams every 10s, sync-detection-findings every 15s -- shortened for THIS "
            f"verification run only, see _beat_schedule_override.py)"
        )
        await asyncio.sleep(
            8
        )  # let both processes finish booting (worker_init wiring, beat's own first tick)
        check("real worker process is alive after boot", worker_proc.poll() is None)
        check("real beat process is alive after boot", beat_proc.poll() is None)

        t0 = datetime.now(UTC)
        log(f"T0 (worker+beat confirmed alive, BEFORE any real telemetry exists): {t0.isoformat()}")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print(
            f"1. Real events onto the real Redis stream directly (org={org_alias}, source={source_id})"
        )
        print("=" * 78)
        redis = AsyncRedis.from_url(REDIS_DSN)
        stream_adapter = RedisStreamIngestAdapter(redis)
        engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
        sealed_batch_repo = PostgresSealedBatchRepository(engine)

        # Real baseline capture, BEFORE producing anything. org_id is a
        # genuinely fresh Keycloak org created moments ago (see step -1
        # above), so this MUST come back None -- asserted for real below,
        # not assumed, since an earlier version of this script reused the
        # one pre-existing kronos-dev org and this exact baseline read is
        # what would have (and, in that version, did) come back non-None,
        # the live signal that (org_id, source_id) pair already carried real
        # sealed_batches history that a fresh run cannot safely seal past
        # (see the `_check_watermark_gap` root cause documented on
        # `source_id`'s own assignment above). Kept as a real, asserted
        # invariant rather than deleted, so a future regression (e.g. org
        # creation silently reusing an alias) fails loudly here instead of
        # producing a silent false PASS on `poll_last_sealed` below.
        baseline1 = await sealed_batch_repo.get_last_sealed(org_id, source_id)
        check(
            "fresh org has NO prior sealed_batches watermark for this source_id",
            baseline1 is None,
            f"unexpected baseline={baseline1.batch_id if baseline1 is not None else None}",
        )
        baseline1_batch_id = baseline1.batch_id if baseline1 is not None else None

        # Defensive fresh-start: org_id is brand new (step -1), so this
        # stream key cannot have any pre-existing entries -- this delete is
        # a true no-op in the normal case, kept only so a stray leftover
        # from an aborted PRIOR attempt at reusing this exact org_id (e.g. a
        # crashed run that created the org but never reached teardown, and
        # this run's own alias/uuid collided, which raw_create_org's own
        # uniqueness suffix makes practically impossible) can never silently
        # inflate this run's own "exactly 3" round-1 assertion below.
        await redis.delete(f"kronos:stream:{org_id}:{source_id}")

        for i in range(3):
            await stream_adapter.produce(org_id, source_id, json.dumps(benign_event(i)).encode())
        t1 = datetime.now(UTC)
        log(f"T1 (round-1 events produced onto real Redis stream): {t1.isoformat()}")

        entries = await redis.xrange(f"kronos:stream:{org_id}:{source_id}")
        check(
            "real Redis XRANGE shows exactly 3 round-1 entries",
            len(entries) == 3,
            f"count={len(entries)}",
        )

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("2. WAIT for the real beat schedule to autonomously seal + normalize batch #1")
        print("=" * 78)
        print("(no manual seal_pending()/normalize_batch() call anywhere below this line)")

        async def poll_last_sealed(prior_batch_id, timeout_s: float):  # noqa: ANN001, ANN202
            deadline = time.time() + timeout_s
            while time.time() < deadline:
                batch = await sealed_batch_repo.get_last_sealed(org_id, source_id)
                if batch is not None and batch.batch_id != prior_batch_id:
                    return batch, datetime.now(UTC)
                await asyncio.sleep(3)
            return None, None

        sealed1, t_sealed1 = await poll_last_sealed(baseline1_batch_id, 120)
        check(
            "real BatchSealingService.seal_pending() sealed batch #1 AUTONOMOUSLY (beat-triggered)",
            sealed1 is not None,
            f"batch_id={sealed1.batch_id if sealed1 else None} sealed_at_wallclock={t_sealed1.isoformat() if t_sealed1 else None}",
        )
        assert sealed1 is not None and t_sealed1 is not None
        log(
            f"T_sealed1 (real Postgres sealed_batches row observed, beat-triggered): {t_sealed1.isoformat()} "
            f"(+{(t_sealed1 - t1).total_seconds():.1f}s after T1)"
        )

        os_client = httpx.Client(base_url=OS_URL, auth=OS_ADMIN, verify=False, timeout=30)
        index_name_pattern = f"kronos-{org_alias.lower()}-stream-{source_id}"

        async def poll_doc_count(batch_id, expected: int, timeout_s: float):  # noqa: ANN001, ANN202
            # Scoped to THIS run's own real batch_id (kronos.batch_id term
            # query -- the same real, established idiom
            # poc/l3_chain_collector_to_detect/run_poc.py's own step-2
            # duplicate check already uses), not a raw match_all count. Since
            # org_alias is a fresh, run-unique org (step -1 above), this
            # run's own index (`kronos-{org_alias}-stream-zeek-conn-log-*`)
            # should be genuinely new -- but batch_id-scoping is kept anyway
            # (defense in depth, zero extra cost) rather than relying on
            # index freshness alone: a raw match_all count would silently
            # pass against ANY doc that happened to land in a same-named
            # index, never actually proving THIS run's own new batch was
            # normalized -- exactly the kind of unverified-looking-correct
            # check CLAUDE.md SS F exists to prevent.
            deadline = time.time() + timeout_s
            while time.time() < deadline:
                resp = os_client.post(
                    f"/{index_name_pattern}-*/_search",
                    json={"query": {"term": {"kronos.batch_id": str(batch_id)}}, "size": 50},
                )
                if resp.status_code == 200:
                    hits = resp.json().get("hits", {}).get("hits", [])
                    if len(hits) >= expected:
                        return hits, datetime.now(UTC)
                await asyncio.sleep(3)
            return [], None

        hits1, t_norm1 = await poll_doc_count(sealed1.batch_id, 3, 90)
        check(
            "real StreamNormalizationService.normalize_batch() indexed batch #1 AUTONOMOUSLY (event-chained)",
            len(hits1) >= 3,
            f"count={len(hits1)}",
        )
        assert t_norm1 is not None
        log(
            f"T_normalized1 (real OpenSearch docs observed, event-chained from seal_pending_streams): "
            f"{t_norm1.isoformat()} (+{(t_norm1 - t_sealed1).total_seconds():.1f}s after T_sealed1)"
        )

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print(
            "3. Real SA field-alias mapping + real per-org SA detector (C1/C2's own verified mechanism)"
        )
        print("=" * 78)
        real_index_name = hits1[0]["_index"]
        alias_mappings = {
            "properties": {
                "id.orig_h": {"type": "alias", "path": "source.ip"},
                "id.resp_h": {"type": "alias", "path": "destination.ip"},
                "id.resp_p": {"type": "alias", "path": "destination.port"},
            }
        }
        map_resp = os_client.post(
            "/_plugins/_security_analytics/mappings",
            json={
                "index_name": real_index_name,
                "rule_topic": "network",
                "partial": True,
                "alias_mappings": alias_mappings,
            },
        )
        check(
            "real SA field-alias mapping POST accepted (200)",
            map_resp.status_code == 200,
            map_resp.text[:200],
        )

        rules_resp = os_client.post(
            "/_plugins/_security_analytics/rules/_search",
            params={"pre_packaged": "true"},
            json={
                "size": 10000,
                "query": {
                    "nested": {"path": "rule", "query": {"match": {"rule.category": "network"}}}
                },
            },
        )
        rules_resp.raise_for_status()
        rule_ids = [hit["_id"] for hit in rules_resp.json().get("hits", {}).get("hits", [])]
        check(
            "real prepackaged 'network' rules fetched, including known-good target rule",
            TARGET_RULE_ID in rule_ids,
        )

        stream_index_pattern = f"{index_name_pattern}-*"
        detector_body = {
            "name": detector_name,
            "detector_type": "network",
            "enabled": True,
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
            "inputs": [
                {
                    "detector_input": {
                        "description": "W1 autonomous-pipeline PoC -- scoped to this run's own fresh stream index",
                        "indices": [stream_index_pattern],
                        "pre_packaged_rules": [{"id": rid} for rid in rule_ids],
                        "custom_rules": [],
                    }
                }
            ],
            "triggers": [],
        }
        detector_resp = os_client.post(
            "/_plugins/_security_analytics/detectors", json=detector_body
        )
        check(
            "real detector created (201), AFTER round-1 index already existed",
            detector_resp.status_code == 201,
            detector_resp.text[:200],
        )
        detector_resp.raise_for_status()
        log(f"real detector created: {detector_name} indices={stream_index_pattern}")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print(
            "4. ROUND 2: real trigger event onto the real Redis stream, strictly AFTER detector creation"
        )
        print("=" * 78)
        public_source_ip = "203.0.113.77"  # TEST-NET-3 (RFC 5737), public/documentation range

        await stream_adapter.produce(org_id, source_id, json.dumps(benign_event(100)).encode())
        await stream_adapter.produce(
            org_id, source_id, json.dumps(malicious_rdp_event(public_source_ip)).encode()
        )
        t2 = datetime.now(UTC)
        log(f"T2 (round-2 trigger event produced onto real Redis stream): {t2.isoformat()}")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("5. WAIT for the real beat schedule to autonomously seal + normalize batch #2")
        print("=" * 78)
        # Round-2's poll budget must comfortably clear the real, production
        # _SEAL_MAX_AGE_SECONDS=60.0 threshold (celery_streaming.py) PLUS at
        # least 1-2 more real beat-tick intervals (10s each, this PoC's own
        # shortened schedule) -- not just barely reach 60s. Round 1 observed
        # T_sealed1 at +72.1s after T1 against a 120s budget; a bare 60s
        # budget here previously raced the very next beat tick and lost
        # (see git history/PoC run log for the prior failure). 100s leaves
        # >3 extra beat ticks of margin past the 60s threshold.
        sealed2, t_sealed2 = await poll_last_sealed(sealed1.batch_id, 100)
        check(
            "real seal_pending_streams sealed batch #2 AUTONOMOUSLY (contains the RDP trigger event)",
            sealed2 is not None,
        )
        assert sealed2 is not None and t_sealed2 is not None
        log(
            f"T_sealed2: {t_sealed2.isoformat()} (+{(t_sealed2 - t2).total_seconds():.1f}s after T2)"
        )

        hits2, t_norm2 = await poll_doc_count(sealed2.batch_id, 2, 90)
        check(
            "real normalize_stream_batch indexed batch #2 AUTONOMOUSLY (event-chained)",
            len(hits2) >= 2,
            f"count={len(hits2)}",
        )
        assert t_norm2 is not None
        log(
            f"T_normalized2: {t_norm2.isoformat()} (+{(t_norm2 - t_sealed2).total_seconds():.1f}s after T_sealed2)"
        )

        trigger_doc = next(
            (h for h in hits2 if h["_source"].get("source", {}).get("ip") == public_source_ip), None
        )
        check(
            "real indexed trigger document's source.ip alias-resolves correctly (public IP)",
            trigger_doc is not None,
        )
        trigger_doc_id = trigger_doc["_id"] if trigger_doc else None
        trigger_index = trigger_doc["_index"] if trigger_doc else None

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("6. WAIT for the real SA monitor's own scheduled execution to fire")
        print("=" * 78)
        deadline = time.time() + 300
        findings_hits: list[dict] = []
        while time.time() < deadline:
            fr = os_client.post(
                "/.opensearch-sap-*-findings-*/_search",
                json={"size": 50, "query": {"term": {"monitor_name": detector_name}}},
            )
            if fr.status_code == 200:
                findings_hits = fr.json().get("hits", {}).get("hits", [])
            if findings_hits:
                break
            await asyncio.sleep(15)
        check(
            "at least one real SA finding produced for this run's own fresh detector",
            len(findings_hits) > 0,
            f"total={len(findings_hits)}",
        )
        t_finding = datetime.now(UTC) if findings_hits else None
        if t_finding:
            log(f"T_finding (real SA monitor fired on its OWN schedule): {t_finding.isoformat()}")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print(
            "7. WAIT for the real beat schedule to autonomously sync this finding into a Detection row"
        )
        print("=" * 78)
        print("(no manual sync_org_findings() call anywhere in this script)")
        detection_repo = PostgresDetectionRepository(engine)

        async def poll_new_detection(timeout_s: float):  # noqa: ANN202
            deadline = time.time() + timeout_s
            while time.time() < deadline:
                async for d in detection_repo.stream_by_org(org_id):
                    if trigger_doc_id is not None and trigger_doc_id in d.matched_document_ids:
                        return d, datetime.now(UTC)
                await asyncio.sleep(5)
            return None, None

        detection, t_detected = await poll_new_detection(180)
        check(
            "real DetectionSyncService.sync_org_findings() created a real Detection row AUTONOMOUSLY (beat-triggered)",
            detection is not None,
        )
        assert detection is not None and t_detected is not None
        log(
            f"T_detected (real Postgres detections row observed, beat-triggered): {t_detected.isoformat()}"
        )
        check(
            "real Detection row's org_id == the real Keycloak org (computed, never read from the finding)",
            detection.org_id == org_id,
        )
        check(
            "real Detection row carries the real target ATT&CK tag",
            TARGET_RULE_TAG in detection.attack_tags,
            str(detection.attack_tags),
        )

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print(
            "8. Honest provenance-linkage check: Detection -> matched_document_ids -> real OpenSearch doc -> kronos.batch_id"
        )
        print("=" * 78)
        doc_get = os_client.get(f"/{trigger_index}/_doc/{trigger_doc_id}")
        check("real GET of the linked trigger document succeeds", doc_get.status_code == 200)
        linked_kronos = doc_get.json().get("_source", {}).get("kronos", {})
        check(
            "linked document's real kronos.batch_id matches real sealed batch #2",
            linked_kronos.get("batch_id") == str(sealed2.batch_id),
            f"doc kronos.batch_id={linked_kronos.get('batch_id')}",
        )
        check(
            "linked document's real kronos.source_id matches our real source_id",
            linked_kronos.get("source_id") == source_id,
        )

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print(
            "9. Idempotency: one more real autonomous sync cycle creates zero duplicate Detection rows"
        )
        print("=" * 78)
        await asyncio.sleep(20)  # >= one more real 15s-overridden sync_detection_findings tick

        recount = 0
        async for d in detection_repo.stream_by_org(org_id):
            if trigger_doc_id is not None and trigger_doc_id in d.matched_document_ids:
                recount += 1
        check(
            "re-running the real autonomous sync cycle creates no duplicate Detection rows",
            recount == 1,
            f"count={recount}",
        )

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print(
            "10. Stop the real throwaway worker/beat -- everything above already happened autonomously"
        )
        print("=" * 78)
        for proc, name in ((beat_proc, "beat"), (worker_proc, "worker")):
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            log(f"real throwaway {name} process stopped (pid={proc.pid})")
        worker_proc = None
        beat_proc = None

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print(
            "11. W1 item (d): real HTTP route -> PlaybookExecutionService.execute() -> real (stand-in) SIEM push"
        )
        print("=" * 78)
        hec_server, hec_thread, hec_port = start_http_server(SplunkHecStandInHandler)
        hec_url = f"http://127.0.0.1:{hec_port}/services/collector/event"
        log(f"real HEC-protocol-accurate stand-in listening on {hec_url}")

        audit_svc = AuditLogService(PostgresAuditLogRepository(engine))
        sink = SplunkHecSink(
            hec_url,
            StaticTokenAuthenticator(REAL_TOKEN, header_name="Authorization", scheme="Splunk"),
        )
        mapper = SplunkDetectionMapper()
        push_service = DetectionSinkPushService(sink, mapper, audit_svc)
        registry = PlaybookActionRegistry()
        registry.register(SyncDetectionToSiemAction("splunk", detection_repo, push_service))
        execution_service = PlaybookExecutionService(registry, audit_svc)

        tenant = TenantContext(
            org_id=org_id,
            org_alias=org_alias,
            user_id=uuid.uuid4(),
            username="poc-analyst",
            roles=frozenset({Role.ANALYST}),
            correlation_id=str(uuid.uuid4()),
        )
        app = create_app()
        app.dependency_overrides[get_tenant_context] = lambda: tenant
        app.dependency_overrides[get_detection_repository] = lambda: detection_repo
        app.dependency_overrides[get_playbook_action_registry] = lambda: registry
        app.dependency_overrides[get_playbook_execution_service] = lambda: execution_service

        from httpx import ASGITransport  # noqa: PLC0415

        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://poc") as async_client:
            route_resp = await async_client.post(
                f"/api/detections/{detection.detection_id}/sync-to-siem/splunk"
            )
        check(
            "real HTTP route POST /api/detections/{id}/sync-to-siem/splunk returns 200",
            route_resp.status_code == 200,
            route_resp.text[:300],
        )
        route_body = route_resp.json()
        check(
            "real PlaybookExecutionService.execute() reports succeeded=true",
            route_body.get("succeeded") is True,
            json.dumps(route_body)[:300],
        )
        check(
            "real stand-in SIEM receiver actually received the real HTTP push",
            len(SplunkHecStandInHandler.received) == 1,
            f"count={len(SplunkHecStandInHandler.received)}",
        )
        if SplunkHecStandInHandler.received:
            pushed_event = SplunkHecStandInHandler.received[0]["event"]
            check(
                "the real pushed event carries this run's own real finding_id",
                pushed_event.get("finding_id") == detection.finding_id,
                f"pushed finding_id={pushed_event.get('finding_id')}",
            )

        t_end = datetime.now(UTC)
        log(f"T_end: {t_end.isoformat()}")

        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print(
            "SUMMARY: real wall-clock timestamps, no manual seal/normalize/sync call anywhere above"
        )
        print("=" * 78)
        log(f"T0 (worker+beat alive, empty backlog)      : {t0.isoformat()}")
        log(f"T1 (round-1 events produced)                : {t1.isoformat()}")
        log(
            f"T_sealed1 (autonomous seal)                 : {t_sealed1.isoformat()} (+{(t_sealed1 - t1).total_seconds():.1f}s)"
        )
        log(
            f"T_normalized1 (autonomous, event-chained)   : {t_norm1.isoformat()} (+{(t_norm1 - t_sealed1).total_seconds():.1f}s)"
        )
        log(f"T2 (round-2 trigger event produced)         : {t2.isoformat()}")
        log(
            f"T_sealed2 (autonomous seal)                 : {t_sealed2.isoformat()} (+{(t_sealed2 - t2).total_seconds():.1f}s)"
        )
        log(
            f"T_normalized2 (autonomous, event-chained)   : {t_norm2.isoformat()} (+{(t_norm2 - t_sealed2).total_seconds():.1f}s)"
        )
        if t_finding:
            log(f"T_finding (real SA monitor's OWN schedule)  : {t_finding.isoformat()}")
        log(f"T_detected (autonomous sync -> Detection)   : {t_detected.isoformat()}")
        log(f"T_end (route (d) verified, teardown)        : {t_end.isoformat()}")
        log(
            f"TOTAL wall-clock window T0 -> T_detected     : {(t_detected - t0).total_seconds():.1f}s"
        )

    finally:
        for proc in (worker_proc, beat_proc):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if tsa_server is not None:
            tsa_server.shutdown()
        if hec_server is not None:
            hec_server.shutdown()
        if os_client is not None:
            os_client.close()
        if redis is not None:
            await redis.aclose()
        if engine is not None:
            await engine.dispose()
        if created_org_id is not None:
            try:
                async with httpx.AsyncClient(timeout=15) as raw:
                    admin_token = await get_raw_admin_token(raw)
                    await raw_delete_org(raw, admin_token, created_org_id)
                log(f"real throwaway Keycloak org deleted: id={created_org_id}")
            except Exception as exc:  # noqa: BLE001
                # Teardown-only, best-effort: never mask the real pass/fail
                # result computed below over a real org left behind (the
                # dev realm having one extra, harmless, easily-identified-by
                # -alias org from a failed teardown is a strictly smaller
                # problem than swallowing a real CHECKS failure here).
                log(f"WARNING: failed to delete throwaway Keycloak org {created_org_id}: {exc}")
        log(f"\nwork_dir left for inspection: {work_dir}")
        log(
            "NOTE: real Redis stream entries, real sealed batches (Postgres+MinIO+TSA), real OpenSearch "
            "documents, real findings, and real Detection/audit_log rows this run created are deliberately "
            "left in place as inspectable proof, matching this chain's own precedent (poc/l3_chain_collector_to_detect/)."
        )
        log(
            "NOTE: the throwaway SA detector itself was NOT cleaned up in this run (left for inspection); "
            "it is not part of any committed src/ path."
        )

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    print(f"\n{passed}/{total} real checks passed")
    return 0 if passed == total else 1


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())
