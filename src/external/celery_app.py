"""Celery application and full parse DAG task definitions.

Task graph:
  dispatch_parse (beat/API) → parse_artefact_fast | parse_artefact_heavy
    → finalize_evidence
  abort_orphan_uploads   (beat, hourly) — timeout stuck UPLOADING evidence
  abort_orphan_parses    (beat, hourly) — timeout stuck PARSING evidence
  anchor_audit_log       (beat, daily)  — Merkle-root all events, TSA-anchor
"""

from __future__ import annotations

import logging
import uuid

from celery import Celery
from celery.schedules import crontab

from src.config import Settings
from src.external.logging_config import configure_logging

# Configure structured JSON logging as early as possible (module import
# time), mirroring fastapi_app.py, so Celery worker/beat logs reach the same
# JSON pipeline the app server does (COMP-8) — Celery's own logging setup
# would otherwise override the root logger with its default formatter.
configure_logging()

_settings = Settings()
logger = logging.getLogger(__name__)

celery_app = Celery(
    "kronos",
    broker=_settings.celery_broker_url.get_secret_value(),
    backend=_settings.celery_result_backend.get_secret_value(),
)

from celery.signals import worker_init  # noqa: E402


@worker_init.connect
def _on_worker_init(**_kwargs: object) -> None:
    """Wire real dependencies when a Celery worker process starts."""
    import os  # noqa: PLC0415

    if os.getenv("DATABASE_URL"):
        try:
            from src.external.startup import wire_dependencies_sync  # noqa: PLC0415

            wire_dependencies_sync()
        except Exception as exc:  # noqa: BLE001
            logger.warning("celery worker startup wiring failed: %s", exc)


celery_app.conf.update(
    task_routes={
        "kronos.dispatch_parse": {"queue": "q.index"},
        "kronos.parse_artefact_fast": {"queue": "q.parse.fast"},
        "kronos.parse_artefact_heavy": {"queue": "q.parse.plaso"},
        "kronos.finalize_evidence": {"queue": "q.index"},
        "kronos.abort_orphan_uploads": {"queue": "q.index"},
        "kronos.auto_dispatch_received": {"queue": "q.index"},
        "kronos.abort_orphan_parses": {"queue": "q.index"},
        "kronos.anchor_audit_log": {"queue": "q.index"},
    },
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    beat_schedule={
        "abort-orphan-uploads": {
            "task": "kronos.abort_orphan_uploads",
            "schedule": crontab(minute=0),  # every hour at :00
        },
        "auto-dispatch-received": {
            "task": "kronos.auto_dispatch_received",
            "schedule": crontab(minute=15),  # every hour at :15 — re-enqueues stuck RECEIVED
        },
        "abort-orphan-parses": {
            "task": "kronos.abort_orphan_parses",
            "schedule": crontab(minute=30),  # every hour at :30
        },
        "anchor-audit-log": {
            "task": "kronos.anchor_audit_log",
            "schedule": crontab(hour=2, minute=0),  # 02:00 UTC daily
        },
    },
    timezone="UTC",
)


# ---------------------------------------------------------------------------
# Helper: build tenant context
# ---------------------------------------------------------------------------


def _tenant(org_id: str, user_id: str):  # type: ignore[return]
    from src.external.dependencies import _build_tenant_from_task  # noqa: PLC0415

    return _build_tenant_from_task(org_id, user_id)


# ---------------------------------------------------------------------------
# dispatch_parse: entry point for the parsing DAG
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.dispatch_parse", bind=True, max_retries=0)  # type: ignore[untyped-decorator]
def dispatch_parse(
    self: object,
    evidence_id: str,
    *,
    org_id: str,
    user_id: str,
    parser_type: str = "fast",
) -> str:
    """Select the correct parse queue and chain finalize_evidence.

    Returns the evidence_id so downstream tasks can look it up.
    """
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    tenant = _tenant(org_id, user_id)

    async def _work(resources):  # type: ignore[no-untyped-def]
        await resources.orchestration_service.start_parsing(uuid.UUID(evidence_id), tenant)

    run_evidence_coro(_work)
    logger.info(
        "dispatch_parse_done", extra={"evidence_id": evidence_id, "parser_type": parser_type}
    )
    return evidence_id


# ---------------------------------------------------------------------------
# parse_artefact_fast: gVisor-sandboxed EVTX / CloudTrail / Nginx parsing
# ---------------------------------------------------------------------------


@celery_app.task(  # type: ignore[untyped-decorator]
    name="kronos.parse_artefact_fast",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    queue="q.parse.fast",
)
def parse_artefact_fast(self: object, evidence_id: str, *, org_id: str, user_id: str) -> dict:  # type: ignore[return]
    """Fast parse task — runs in gVisor sandbox.

    Returns {evidence_id, record_count} for finalize_evidence.
    """
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    tenant = _tenant(org_id, user_id)

    async def _work(resources):  # type: ignore[no-untyped-def]
        return await resources.orchestration_service.execute_parse(uuid.UUID(evidence_id), tenant)

    try:
        count = run_evidence_coro(_work)
        result = {"evidence_id": evidence_id, "record_count": count}
        finalize_evidence.apply_async(
            kwargs={"parse_result": result, "org_id": org_id, "user_id": user_id},
            queue="q.index",
        )
        return result
    except Exception as exc:
        logger.error("parse_fast_failed", extra={"evidence_id": evidence_id, "error": str(exc)})
        raise self.retry(exc=exc)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# parse_artefact_heavy: Plaso in Firecracker microVM
# ---------------------------------------------------------------------------


@celery_app.task(  # type: ignore[untyped-decorator]
    name="kronos.parse_artefact_heavy",
    bind=True,
    max_retries=2,
    default_retry_delay=120,
    queue="q.parse.plaso",
    time_limit=600,
    soft_time_limit=540,
)
def parse_artefact_heavy(self: object, evidence_id: str, *, org_id: str, user_id: str) -> dict:  # type: ignore[return]
    """Heavy parse task — delegates to Plaso via FirecrackerLauncher.

    Returns {evidence_id, record_count} for finalize_evidence.
    """
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    tenant = _tenant(org_id, user_id)

    async def _work(resources):  # type: ignore[no-untyped-def]
        return await resources.orchestration_service.execute_parse(uuid.UUID(evidence_id), tenant)

    try:
        count = run_evidence_coro(_work)
        result = {"evidence_id": evidence_id, "record_count": count}
        finalize_evidence.apply_async(
            kwargs={"parse_result": result, "org_id": org_id, "user_id": user_id},
            queue="q.index",
        )
        return result
    except Exception as exc:
        logger.error("parse_heavy_failed", extra={"evidence_id": evidence_id, "error": str(exc)})
        raise self.retry(exc=exc)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# finalize_evidence: emit final audit event after successful parse
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.finalize_evidence", bind=True, max_retries=3)  # type: ignore[untyped-decorator]
def finalize_evidence(
    self: object,
    parse_result: dict,
    *,
    org_id: str,
    user_id: str,
) -> None:
    """Emit INGEST_COMPLETED audit event after a successful parse.

    Chained after parse_artefact_* so it runs only on success.
    """
    from src.domain.audit import AuditEventType  # noqa: PLC0415
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    evidence_id = parse_result.get("evidence_id", "")
    record_count = parse_result.get("record_count", 0)

    tenant = _tenant(org_id, user_id)

    async def _work(resources):  # type: ignore[no-untyped-def]
        await resources.audit_log_service.log(
            AuditEventType.INGEST_COMPLETED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            details={"evidence_id": evidence_id, "record_count": record_count},
        )

    try:
        run_evidence_coro(_work)
        logger.info(
            "finalize_evidence_done", extra={"evidence_id": evidence_id, "records": record_count}
        )
    except Exception as exc:
        logger.error(
            "finalize_evidence_failed", extra={"evidence_id": evidence_id, "error": str(exc)}
        )
        raise self.retry(exc=exc)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# abort_orphan_uploads: hourly cleanup of stuck UPLOADING evidence
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.abort_orphan_uploads", bind=True, max_retries=1)  # type: ignore[untyped-decorator]
def abort_orphan_uploads(self: object) -> int:
    """Transition evidence stuck in UPLOADING for >2 h to ERROR.

    Returns count of aborted items.
    """
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from pydantic import ValidationError  # noqa: PLC0415

    from src.domain.audit import AuditEventType  # noqa: PLC0415
    from src.domain.evidence import EvidenceState  # noqa: PLC0415
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    cutoff = datetime.now(UTC) - timedelta(hours=2)

    try:

        async def _work(resources):  # type: ignore[no-untyped-def]
            count = 0
            async for ev in resources.evidence_repository.stream_all_by_state(
                EvidenceState.UPLOADING
            ):
                if ev.created_at < cutoff:
                    aborted = ev.with_error("upload_timeout")
                    await resources.evidence_repository.update(aborted)
                    await resources.audit_log_service.log(
                        AuditEventType.EVIDENCE_ERROR,
                        org_id=ev.metadata.org_id,
                        evidence_id=ev.evidence_id,
                        details={"reason": "upload_timeout", "cutoff": cutoff.isoformat()},
                    )
                    count += 1
            return count

        count = run_evidence_coro(_work)
    except (RuntimeError, ValidationError):
        count = 0
        logger.warning("abort_orphan_uploads: repository not configured; skipping")
    logger.info("abort_orphan_uploads_done", extra={"aborted": count})
    return count


# ---------------------------------------------------------------------------
# abort_orphan_parses: hourly cleanup of stuck PARSING evidence
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.abort_orphan_parses", bind=True, max_retries=1)  # type: ignore[untyped-decorator]
def abort_orphan_parses(self: object) -> int:
    """Transition evidence stuck in PARSING for >3 h to ERROR.

    Returns count of aborted items.
    """
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from pydantic import ValidationError  # noqa: PLC0415

    from src.domain.audit import AuditEventType  # noqa: PLC0415
    from src.domain.evidence import EvidenceState  # noqa: PLC0415
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    cutoff = datetime.now(UTC) - timedelta(hours=3)

    try:

        async def _work(resources):  # type: ignore[no-untyped-def]
            count = 0
            async for ev in resources.evidence_repository.stream_all_by_state(
                EvidenceState.PARSING
            ):
                if ev.updated_at < cutoff:
                    aborted = ev.with_error("parse_timeout")
                    await resources.evidence_repository.update(aborted)
                    await resources.audit_log_service.log(
                        AuditEventType.PARSE_FAILED,
                        org_id=ev.metadata.org_id,
                        evidence_id=ev.evidence_id,
                        details={"reason": "parse_timeout", "cutoff": cutoff.isoformat()},
                    )
                    count += 1
            return count

        count = run_evidence_coro(_work)
    except (RuntimeError, ValidationError):
        count = 0
        logger.warning("abort_orphan_parses: repository not configured; skipping")
    logger.info("abort_orphan_parses_done", extra={"aborted": count})
    return count


# ---------------------------------------------------------------------------
# auto_dispatch_received: hourly re-enqueue of evidence stuck in RECEIVED
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.auto_dispatch_received", bind=True, max_retries=1)  # type: ignore[untyped-decorator]
def auto_dispatch_received(self: object) -> int:
    """Re-enqueue dispatch_parse for evidence stuck in RECEIVED longer than 5 min.

    Safety net for cases where the initial auto-dispatch in EvidenceIntakeService
    failed (e.g., broker unreachable at upload time).  Runs every hour at :15.
    Returns count of re-dispatched items.
    """
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from pydantic import ValidationError  # noqa: PLC0415

    from src.adapter.queue.celery_queue import CeleryTaskQueue  # noqa: PLC0415
    from src.domain.evidence import EvidenceState  # noqa: PLC0415
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    cutoff = datetime.now(UTC) - timedelta(minutes=5)

    try:
        queue = CeleryTaskQueue()

        async def _work(resources):  # type: ignore[no-untyped-def]
            count = 0
            async for ev in resources.evidence_repository.stream_all_by_state(
                EvidenceState.RECEIVED
            ):
                if ev.updated_at < cutoff:
                    tenant = _tenant(str(ev.metadata.org_id), str(ev.metadata.uploader_user_id))
                    try:
                        await queue.enqueue_dispatch(ev.evidence_id, tenant)
                        count += 1
                        logger.info(
                            "auto_dispatch_reenqueued",
                            extra={"evidence_id": str(ev.evidence_id)},
                        )
                    except Exception as exc:
                        logger.error(
                            "auto_dispatch_enqueue_failed",
                            extra={"evidence_id": str(ev.evidence_id), "error": str(exc)},
                        )
            return count

        count = run_evidence_coro(_work)
    except (RuntimeError, ValidationError):
        count = 0
        logger.warning("auto_dispatch_received: repository not configured; skipping")
    logger.info("auto_dispatch_received_done", extra={"dispatched": count})
    return count


# ---------------------------------------------------------------------------
# anchor_audit_log: daily Merkle-root + RFC 3161 TSA anchoring
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.anchor_audit_log", bind=True, max_retries=3)  # type: ignore[untyped-decorator]
def anchor_audit_log(self: object) -> dict[str, str]:
    """Anchor yesterday's audit log: one Merkle root + TSA anchor per active org.

    The hash chain (and its sequence_number) is per-org (see
    ``AuditLogRepository.append_atomic``), so a "day" Merkle root only makes
    sense computed over one org's events at a time.  This task:

      1. Uses ``list_by_date_range`` (AUDIT-01) — the one legitimate
         cross-org query, restricted to this system beat task per
         CLAUDE.md §E.5 — to discover which orgs had activity yesterday.
      2. Calls ``AuditLogService.anchor_day()`` (AUDIT-03) once per org —
         the single code path that builds the canonical Merkle root, calls
         the RFC 3161 TSA, and persists the anchor — instead of
         reimplementing Merkle-building inline and never calling the TSA.

    Returns ``{org_id: root_hash}`` for every org anchored.
    """
    from datetime import UTC, date, datetime, timedelta  # noqa: PLC0415

    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415
    from src.external.dependencies import get_timestamp_service  # noqa: PLC0415

    async def _work(resources):  # type: ignore[no-untyped-def]
        timestamp_service = get_timestamp_service()

        yesterday = date.today() - timedelta(days=1)
        day_start = datetime(yesterday.year, yesterday.month, yesterday.day, tzinfo=UTC)
        day_end = day_start + timedelta(days=1)

        events = await resources.audit_log_repository.list_by_date_range(day_start, day_end)
        org_ids = sorted({e.org_id for e in events if e.org_id is not None}, key=str)

        roots: dict[str, str] = {}
        for org_id in org_ids:
            root = await resources.audit_log_service.anchor_day(
                yesterday, org_id, timestamp_service
            )
            roots[str(org_id)] = root

        logger.info(
            "audit_log_anchored",
            extra={"day": yesterday.isoformat(), "orgs_anchored": len(roots)},
        )
        return roots

    return run_evidence_coro(_work)
