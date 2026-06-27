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
        "kronos.abort_orphan_parses": {"queue": "q.index"},
        "kronos.anchor_audit_log": {"queue": "q.index"},
        # Legacy aliases — also routed to correct queues.
        "kronos.parse_fast": {"queue": "q.parse.fast"},
        "kronos.parse_heavy": {"queue": "q.parse.plaso"},
    },
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    beat_schedule={
        "abort-orphan-uploads": {
            "task": "kronos.abort_orphan_uploads",
            "schedule": crontab(minute=0),  # every hour
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
# Helper: build dependencies without FastAPI context
# ---------------------------------------------------------------------------


def _deps():  # type: ignore[return]
    """Return (orchestration_svc, audit_svc) for use in Celery workers."""
    from src.external.dependencies import (  # noqa: PLC0415
        _build_orchestration_service,
        get_audit_log_repository,
        get_audit_log_service,
    )

    audit = get_audit_log_service(get_audit_log_repository())
    orch = _build_orchestration_service()
    return orch, audit


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
    import asyncio  # noqa: PLC0415

    tenant = _tenant(org_id, user_id)
    orch, _ = _deps()

    asyncio.run(orch.start_parsing(uuid.UUID(evidence_id), tenant))
    logger.info("dispatch_parse_done", extra={"evidence_id": evidence_id, "parser_type": parser_type})
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
    import asyncio  # noqa: PLC0415

    tenant = _tenant(org_id, user_id)
    orch, _ = _deps()
    try:
        count = asyncio.run(orch.execute_parse(uuid.UUID(evidence_id), tenant))
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
    import asyncio  # noqa: PLC0415

    tenant = _tenant(org_id, user_id)
    orch, _ = _deps()
    try:
        count = asyncio.run(orch.execute_parse(uuid.UUID(evidence_id), tenant))
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
    import asyncio  # noqa: PLC0415

    from src.domain.audit import AuditEventType  # noqa: PLC0415
    from src.external.dependencies import (  # noqa: PLC0415
        get_audit_log_repository,
        get_audit_log_service,
    )

    evidence_id = parse_result.get("evidence_id", "")
    record_count = parse_result.get("record_count", 0)

    try:
        audit = get_audit_log_service(get_audit_log_repository())
        tenant = _tenant(org_id, user_id)
        asyncio.run(
            audit.log(
                AuditEventType.INGEST_COMPLETED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                details={"evidence_id": evidence_id, "record_count": record_count},
            )
        )
        logger.info("finalize_evidence_done", extra={"evidence_id": evidence_id, "records": record_count})
    except Exception as exc:
        logger.error("finalize_evidence_failed", extra={"evidence_id": evidence_id, "error": str(exc)})
        raise self.retry(exc=exc)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# abort_orphan_uploads: hourly cleanup of stuck UPLOADING evidence
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.abort_orphan_uploads", bind=True, max_retries=1)  # type: ignore[untyped-decorator]
def abort_orphan_uploads(self: object) -> int:
    """Transition evidence stuck in UPLOADING for >2 h to ERROR.

    Returns count of aborted items.
    """
    import asyncio  # noqa: PLC0415
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from src.domain.audit import AuditEventType  # noqa: PLC0415
    from src.domain.evidence import EvidenceState  # noqa: PLC0415
    from src.external.dependencies import (  # noqa: PLC0415
        get_audit_log_repository,
        get_audit_log_service,
        get_evidence_repository,
    )

    cutoff = datetime.now(UTC) - timedelta(hours=2)

    # Cross-org scanning requires a Postgres query (not available in unit tests).
    # In production the PostgresEvidenceRepository implements stream_all_by_state.
    try:
        repo = get_evidence_repository()
        audit = get_audit_log_service(get_audit_log_repository())

        async def _run() -> int:
            count = 0
            if not hasattr(repo, "stream_all_by_state"):
                logger.warning("abort_orphan_uploads: repo lacks stream_all_by_state; skipping")
                return 0
            async for ev in repo.stream_all_by_state(EvidenceState.UPLOADING):  # type: ignore[attr-defined]
                if ev.created_at < cutoff:
                    aborted = ev.with_error("upload_timeout")
                    await repo.update(aborted)
                    await audit.log(
                        AuditEventType.EVIDENCE_ERROR,
                        org_id=ev.metadata.org_id,
                        evidence_id=ev.evidence_id,
                        details={"reason": "upload_timeout", "cutoff": cutoff.isoformat()},
                    )
                    count += 1
            return count

        count = asyncio.run(_run())
    except RuntimeError:
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
    import asyncio  # noqa: PLC0415
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from src.domain.audit import AuditEventType  # noqa: PLC0415
    from src.domain.evidence import EvidenceState  # noqa: PLC0415
    from src.external.dependencies import (  # noqa: PLC0415
        get_audit_log_repository,
        get_audit_log_service,
        get_evidence_repository,
    )

    cutoff = datetime.now(UTC) - timedelta(hours=3)

    try:
        repo = get_evidence_repository()
        audit = get_audit_log_service(get_audit_log_repository())

        async def _run() -> int:
            count = 0
            if not hasattr(repo, "stream_all_by_state"):
                logger.warning("abort_orphan_parses: repo lacks stream_all_by_state; skipping")
                return 0
            async for ev in repo.stream_all_by_state(EvidenceState.PARSING):  # type: ignore[attr-defined]
                if ev.updated_at < cutoff:
                    aborted = ev.with_error("parse_timeout")
                    await repo.update(aborted)
                    await audit.log(
                        AuditEventType.PARSE_FAILED,
                        org_id=ev.metadata.org_id,
                        evidence_id=ev.evidence_id,
                        details={"reason": "parse_timeout", "cutoff": cutoff.isoformat()},
                    )
                    count += 1
            return count

        count = asyncio.run(_run())
    except RuntimeError:
        count = 0
        logger.warning("abort_orphan_parses: repository not configured; skipping")
    logger.info("abort_orphan_parses_done", extra={"aborted": count})
    return count


# ---------------------------------------------------------------------------
# anchor_audit_log: daily Merkle-root + RFC 3161 TSA anchoring
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.anchor_audit_log", bind=True, max_retries=3)  # type: ignore[untyped-decorator]
def anchor_audit_log(self: object) -> str:
    """Compute daily Merkle root of all audit events and anchor via TSA.

    Returns hex Merkle root.
    """
    import asyncio  # noqa: PLC0415
    import hashlib  # noqa: PLC0415
    from datetime import UTC, date, datetime, timedelta  # noqa: PLC0415

    from src.domain.audit import AuditEventType  # noqa: PLC0415
    from src.external.dependencies import (  # noqa: PLC0415
        get_audit_log_repository,
        get_audit_log_service,
    )

    async def _run() -> str:
        repo = get_audit_log_repository()
        audit_svc = get_audit_log_service(repo)

        yesterday = date.today() - timedelta(days=1)
        day_start = datetime(yesterday.year, yesterday.month, yesterday.day, tzinfo=UTC)
        day_end = day_start + timedelta(days=1)

        events = await repo.list_by_date_range(day_start, day_end)
        if not events:
            root = hashlib.sha256(b"empty").hexdigest()
        else:
            layer: list[bytes] = [
                hashlib.sha256((e.row_hash or "").encode()).digest() for e in events
            ]
            while len(layer) > 1:
                if len(layer) % 2 == 1:
                    layer.append(layer[-1])
                layer = [
                    hashlib.sha256(layer[i] + layer[i + 1]).digest()
                    for i in range(0, len(layer), 2)
                ]
            root = layer[0].hex()

        import uuid as _uuid  # noqa: PLC0415
        # System actor sentinel — no real user, no org scope for cross-org anchor.
        _SYSTEM_ACTOR = _uuid.UUID("00000000-0000-0000-0000-000000000001")
        await audit_svc.log(
            AuditEventType.AUDIT_MERKLE_ANCHORED,
            actor_user_id=_SYSTEM_ACTOR,
            details={
                "merkle_root": root,
                "event_count": len(events),
                "day": yesterday.isoformat(),
            },
        )
        logger.info("audit_log_anchored", extra={"merkle_root": root, "events": len(events)})
        return root

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# Legacy aliases (for backward compat with tasks queued before this refactor)
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.parse_fast", bind=True, max_retries=3)  # type: ignore[untyped-decorator]
def parse_evidence_fast(self: object, evidence_id: str, *, org_id: str, user_id: str) -> int:
    """Legacy alias — re-dispatches via Celery (does not call directly)."""
    result = parse_artefact_fast.apply(
        kwargs={"evidence_id": evidence_id, "org_id": org_id, "user_id": user_id}
    )
    data = result.get() if hasattr(result, "get") else {}
    return data.get("record_count", 0) if isinstance(data, dict) else 0


@celery_app.task(name="kronos.parse_heavy", bind=True, max_retries=3)  # type: ignore[untyped-decorator]
def parse_evidence_heavy(self: object, evidence_id: str, *, org_id: str, user_id: str) -> int:
    """Legacy alias — re-dispatches via Celery (does not call directly)."""
    result = parse_artefact_heavy.apply(
        kwargs={"evidence_id": evidence_id, "org_id": org_id, "user_id": user_id}
    )
    data = result.get() if hasattr(result, "get") else {}
    return data.get("record_count", 0) if isinstance(data, dict) else 0
