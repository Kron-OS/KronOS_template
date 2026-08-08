"""Celery application and full parse DAG task definitions.

Task graph:
  process_intake (API finalize_upload / retry-intake) → validate/scan/hash/promote
    → dispatch_parse (auto-enqueued by _promote()) → parse_artefact_fast | parse_artefact_heavy
    → finalize_evidence
  abort_orphan_uploads   (beat, hourly) — timeout stuck UPLOADING evidence
  abort_orphan_intake    (beat, hourly) — timeout stuck SCANNING/HASHING evidence
  abort_orphan_parses    (beat, hourly) — timeout stuck PARSING evidence
  anchor_audit_log       (beat, daily)  — Merkle-root all events, TSA-anchor
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Any

from celery import Celery
from celery.schedules import crontab

from src.config import Settings
from src.domain.user import TenantContext
from src.exceptions import EvidenceStateConflictError
from src.external.logging_config import configure_logging

if TYPE_CHECKING:
    from src.external.celery_runtime import TaskResources

# Configure structured JSON logging as early as possible (module import
# time), mirroring fastapi_app.py, so Celery worker/beat logs reach the same
# JSON pipeline the app server does (COMP-8) — Celery's own logging setup
# would otherwise override the root logger with its default formatter.
configure_logging()

_settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars
logger = logging.getLogger(__name__)

celery_app = Celery(
    "kronos",
    broker=_settings.celery_broker_url.get_secret_value(),
    backend=_settings.celery_result_backend.get_secret_value(),
)

from celery.signals import worker_init  # noqa: E402


@worker_init.connect
def _on_worker_init(**_kwargs: object) -> None:
    """Wire real dependencies when a Celery worker process starts.

    Does NOT swallow wiring failures. This used to catch every exception and
    log a warning, which let the worker finish booting — and start accepting
    tasks — even when wire_dependencies_sync() died partway through (e.g. a
    transient DB error while creating tables) and never reached
    configure_dependencies(). Every task dispatched to that worker then
    failed deep in execution with a confusing "EvidenceStorage is not
    configured" instead of the real, immediate cause. Re-raising here makes
    Celery abort worker startup so the failure is loud and the process
    restarts instead of running in a silently broken state.
    """
    import os  # noqa: PLC0415

    if os.getenv("DATABASE_URL"):
        from src.external.startup import wire_dependencies_sync  # noqa: PLC0415

        try:
            wire_dependencies_sync()
        except Exception:
            logger.exception("celery worker startup wiring failed; refusing to start")
            raise


celery_app.conf.update(
    task_routes={
        "kronos.process_intake": {"queue": "q.intake"},
        "kronos.dispatch_parse": {"queue": "q.index"},
        "kronos.parse_artefact_fast": {"queue": "q.parse.fast"},
        "kronos.parse_artefact_heavy": {"queue": "q.parse.plaso"},
        "kronos.finalize_evidence": {"queue": "q.index"},
        "kronos.abort_orphan_uploads": {"queue": "q.index"},
        "kronos.abort_orphan_intake": {"queue": "q.index"},
        "kronos.auto_dispatch_received": {"queue": "q.index"},
        "kronos.abort_orphan_parses": {"queue": "q.index"},
        "kronos.anchor_audit_log": {"queue": "q.index"},
        "kronos.auto_resume_quota_held": {"queue": "q.index"},
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
        "abort-orphan-intake": {
            "task": "kronos.abort_orphan_intake",
            "schedule": crontab(minute=45),  # every hour at :45 — SCANNING/HASHING orphans
        },
        "anchor-audit-log": {
            "task": "kronos.anchor_audit_log",
            "schedule": crontab(hour=2, minute=0),  # 02:00 UTC daily
        },
        "auto-resume-quota-held": {
            "task": "kronos.auto_resume_quota_held",
            # Every 15 min, not hourly like the orphan-cleanup tasks above:
            # unlike those (rare failure conditions), a quota hold is an
            # expected, routine condition that can clear via a path with no
            # direct trigger of its own (evidence purged/deleted elsewhere,
            # dropping usage back under the soft ceiling) -- and every
            # minute it stays held is a minute an analyst's timeline data
            # is missing. The admin quota PATCH route already triggers an
            # immediate resume for the "quota raised" case (see
            # src/external/routes/admin.py); this sweep is the same
            # belt-and-braces safety net auto_dispatch_received provides
            # for its own concern, just on a tighter interval given quota
            # holds are the more common, more analyst-visible case.
            "schedule": crontab(minute="*/15"),
        },
    },
    timezone="UTC",
)


# ---------------------------------------------------------------------------
# Helper: build tenant context
# ---------------------------------------------------------------------------


def _tenant(org_id: str, user_id: str) -> TenantContext:
    from src.external.dependencies import _build_tenant_from_task  # noqa: PLC0415

    return _build_tenant_from_task(org_id, user_id)


# ---------------------------------------------------------------------------
# process_intake: validate/scan/hash/promote (was inline in finalize_upload)
# ---------------------------------------------------------------------------


@celery_app.task(
    name="kronos.process_intake",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    queue="q.intake",
)
def process_intake(self: object, evidence_id: str, *, org_id: str, user_id: str) -> str:
    """Validate/scan/hash/promote a just-uploaded artefact, off the FastAPI thread.

    Real bug this fixes: the old finalize_upload ran this synchronously on
    the request thread; any exception it didn't already anticipate left
    evidence permanently orphaned in SCANNING/HASHING (see
    EvidenceIntakeService.process_intake's own docstring for the full
    account). That method always lands on ERROR with a categorized reason
    on any failure (see domain.evidence.is_retryable_error_reason) --
    ValidationError means a terminal reason (retrying the same bytes can
    never produce a different verdict, e.g. infected/hash_mismatch), so
    only genuinely retryable failures (storage/scanner connectivity, etc.)
    get a Celery-level retry here; ERROR is itself a valid re-entry point
    (evidence.py's ERROR -> SCANNING transition) so a retry just re-runs
    the whole pipeline against the same still-quarantined object.
    """
    from src.exceptions import ValidationError as _ValidationError  # noqa: PLC0415
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    tenant = _tenant(org_id, user_id)

    async def _work(resources: TaskResources) -> str:
        evidence = await resources.intake_service.process_intake(uuid.UUID(evidence_id), tenant)
        return str(evidence.state.value)

    try:
        return run_evidence_coro(_work)
    except _ValidationError as exc:
        logger.error(
            "process_intake_terminal", extra={"evidence_id": evidence_id, "error": str(exc)}
        )
        return "ERROR"
    except Exception as exc:
        logger.error("process_intake_failed", extra={"evidence_id": evidence_id, "error": str(exc)})
        raise self.retry(exc=exc) from exc  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# dispatch_parse: entry point for the parsing DAG
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.dispatch_parse", bind=True, max_retries=0)
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

    async def _work(resources: TaskResources) -> None:
        await resources.orchestration_service.start_parsing(uuid.UUID(evidence_id), tenant)

    run_evidence_coro(_work)
    logger.info(
        "dispatch_parse_done", extra={"evidence_id": evidence_id, "parser_type": parser_type}
    )
    return evidence_id


# ---------------------------------------------------------------------------
# parse_artefact_fast: gVisor-sandboxed EVTX / CloudTrail / Nginx parsing
# ---------------------------------------------------------------------------


@celery_app.task(
    name="kronos.parse_artefact_fast",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    queue="q.parse.fast",
)
def parse_artefact_fast(
    self: object, evidence_id: str, *, org_id: str, user_id: str
) -> dict[str, Any]:
    """Fast parse task — runs in gVisor sandbox.

    Returns {evidence_id, record_count} for finalize_evidence.
    """
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    tenant = _tenant(org_id, user_id)
    # self.request.retries is 0 on the first execution and increments on each
    # self.retry() call, so this is True exactly when calling self.retry()
    # below would exhaust the budget (raise MaxRetriesExceededError) rather
    # than schedule another attempt — i.e. this really is the last chance to
    # parse this evidence. Only then should the orchestration layer flip
    # evidence to the terminal ERROR state; see execute_parse's docstring.
    is_final_attempt = self.request.retries >= self.max_retries  # type: ignore[attr-defined]

    async def _work(resources: TaskResources) -> int:
        return await resources.orchestration_service.execute_parse(
            uuid.UUID(evidence_id), tenant, is_final_attempt=is_final_attempt
        )

    try:
        count = run_evidence_coro(_work)
        result = {"evidence_id": evidence_id, "record_count": count}
        finalize_evidence.apply_async(
            kwargs={"parse_result": result, "org_id": org_id, "user_id": user_id},
            queue="q.index",
        )
        return result
    except EvidenceStateConflictError as exc:
        logger.error(
            "parse_state_conflict",
            extra={"evidence_id": evidence_id, "error": str(exc)},
        )
        raise
    except Exception as exc:
        logger.error("parse_fast_failed", extra={"evidence_id": evidence_id, "error": str(exc)})
        raise self.retry(exc=exc) from exc  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# parse_artefact_heavy: Plaso in Firecracker microVM
# ---------------------------------------------------------------------------


@celery_app.task(
    name="kronos.parse_artefact_heavy",
    bind=True,
    max_retries=2,
    default_retry_delay=120,
    queue="q.parse.plaso",
    time_limit=600,
    soft_time_limit=540,
)
def parse_artefact_heavy(
    self: object, evidence_id: str, *, org_id: str, user_id: str
) -> dict[str, Any]:
    """Heavy parse task — delegates to Plaso via FirecrackerLauncher.

    Returns {evidence_id, record_count} for finalize_evidence.
    """
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    tenant = _tenant(org_id, user_id)
    # See parse_artefact_fast's identical comment: only the true last attempt
    # should flip evidence to the terminal ERROR state.
    is_final_attempt = self.request.retries >= self.max_retries  # type: ignore[attr-defined]

    async def _work(resources: TaskResources) -> int:
        return await resources.orchestration_service.execute_parse(
            uuid.UUID(evidence_id), tenant, is_final_attempt=is_final_attempt
        )

    try:
        count = run_evidence_coro(_work)
        result = {"evidence_id": evidence_id, "record_count": count}
        finalize_evidence.apply_async(
            kwargs={"parse_result": result, "org_id": org_id, "user_id": user_id},
            queue="q.index",
        )
        return result
    except EvidenceStateConflictError as exc:
        logger.error(
            "parse_state_conflict",
            extra={"evidence_id": evidence_id, "error": str(exc)},
        )
        raise
    except Exception as exc:
        logger.error("parse_heavy_failed", extra={"evidence_id": evidence_id, "error": str(exc)})
        raise self.retry(exc=exc) from exc  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# finalize_evidence: emit final audit event after successful parse
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.finalize_evidence", bind=True, max_retries=3)
def finalize_evidence(
    self: object,
    parse_result: dict[str, Any],
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

    async def _work(resources: TaskResources) -> None:
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
        raise self.retry(exc=exc) from exc  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# abort_orphan_uploads: hourly cleanup of stuck UPLOADING evidence
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.abort_orphan_uploads", bind=True, max_retries=1)
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

        async def _work(resources: TaskResources) -> int:
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
# abort_orphan_intake: hourly cleanup of stuck SCANNING/HASHING evidence
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.abort_orphan_intake", bind=True, max_retries=1)
def abort_orphan_intake(self: object) -> int:
    """Transition evidence stuck in SCANNING or HASHING for >30 min to ERROR.

    Defense-in-depth safety net: process_intake's own broad exception
    handling already lands on ERROR on any failure (see its docstring), so
    this should rarely find anything — but a worker crash mid-task (killed,
    OOM, node lost) can still leave evidence orphaned here with no exception
    ever raised to catch. Same shape as abort_orphan_uploads/_parses.
    Returns count of aborted items.
    """
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from pydantic import ValidationError  # noqa: PLC0415

    from src.domain.audit import AuditEventType  # noqa: PLC0415
    from src.domain.evidence import EvidenceState  # noqa: PLC0415
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    cutoff = datetime.now(UTC) - timedelta(minutes=30)

    try:

        async def _work(resources: TaskResources) -> int:
            count = 0
            for state in (EvidenceState.SCANNING, EvidenceState.HASHING):
                async for ev in resources.evidence_repository.stream_all_by_state(state):
                    if ev.updated_at < cutoff:
                        aborted = ev.with_error("intake_timeout")
                        await resources.evidence_repository.update(aborted, expected_state=state)
                        await resources.audit_log_service.log(
                            AuditEventType.EVIDENCE_ERROR,
                            org_id=ev.metadata.org_id,
                            evidence_id=ev.evidence_id,
                            details={"reason": "intake_timeout", "cutoff": cutoff.isoformat()},
                        )
                        count += 1
            return count

        count = run_evidence_coro(_work)
    except (RuntimeError, ValidationError):
        count = 0
        logger.warning("abort_orphan_intake: repository not configured; skipping")
    logger.info("abort_orphan_intake_done", extra={"aborted": count})
    return count


# ---------------------------------------------------------------------------
# abort_orphan_parses: hourly cleanup of stuck PARSING evidence
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.abort_orphan_parses", bind=True, max_retries=1)
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

        async def _work(resources: TaskResources) -> int:
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


@celery_app.task(name="kronos.auto_dispatch_received", bind=True, max_retries=1)
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

        async def _work(resources: TaskResources) -> int:
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
# auto_resume_quota_held: periodic re-check + resume of quota-held evidence
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.auto_resume_quota_held", bind=True, max_retries=1)
def auto_resume_quota_held(self: object) -> int:
    """Re-check every quota-held evidence and re-enqueue dispatch for any
    org that's back under the 1.0x soft ceiling (docs/TENANT_USAGE_QUOTA.md §1
    item 3 -- "auto-resume"). Mirrors auto_dispatch_received's own idiom
    exactly: query the cross-org stream_all_quota_held() (CLAUDE.md §E.5 --
    beat-task-only), then simply re-enqueue dispatch_parse the same way a
    fresh upload's own auto-dispatch does. start_parsing() (the one
    authoritative quota-check point, see ParsingOrchestrationService's own
    comment) does the real is_ingestion_held() re-check and either clears
    quota_held and proceeds, or leaves it held with no new audit spam --
    this task never needs to know which outcome it got.

    Returns count of re-dispatched items.
    """
    from pydantic import ValidationError  # noqa: PLC0415

    from src.adapter.queue.celery_queue import CeleryTaskQueue  # noqa: PLC0415
    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415

    try:
        queue = CeleryTaskQueue()

        async def _work(resources: TaskResources) -> int:
            count = 0
            async for ev in resources.evidence_repository.stream_all_quota_held():
                tenant = _tenant(str(ev.metadata.org_id), str(ev.metadata.uploader_user_id))
                try:
                    await queue.enqueue_dispatch(ev.evidence_id, tenant)
                    count += 1
                    logger.info(
                        "auto_resume_quota_held_reenqueued",
                        extra={
                            "evidence_id": str(ev.evidence_id),
                            "org_id": str(ev.metadata.org_id),
                        },
                    )
                except Exception as exc:
                    logger.error(
                        "auto_resume_quota_held_enqueue_failed",
                        extra={"evidence_id": str(ev.evidence_id), "error": str(exc)},
                    )
            return count

        count = run_evidence_coro(_work)
    except (RuntimeError, ValidationError):
        count = 0
        logger.warning("auto_resume_quota_held: repository not configured; skipping")
    logger.info("auto_resume_quota_held_done", extra={"resumed_candidates": count})
    return count


# ---------------------------------------------------------------------------
# anchor_audit_log: daily Merkle-root + RFC 3161 TSA anchoring
# ---------------------------------------------------------------------------


@celery_app.task(name="kronos.anchor_audit_log", bind=True, max_retries=3)
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
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from src.external.celery_runtime import run_evidence_coro  # noqa: PLC0415
    from src.external.dependencies import get_timestamp_service  # noqa: PLC0415

    async def _work(resources: TaskResources) -> dict[str, str]:
        timestamp_service = get_timestamp_service()

        # UTC date, not local server date (date.today()): every audit event's
        # occurred_at is UTC (AuditLogService.log()'s datetime.now(UTC)
        # default), and the merkle-proof route scopes anchors by
        # occurred_at.date() (UTC). date.today() uses the server's local
        # timezone, which is wrong by exactly one day for roughly 2 hours
        # around local midnight on any server ahead of UTC (e.g. CEST,
        # UTC+2) — reproduced directly (poc/full_pipeline/README.md) and
        # fixed here.
        yesterday = datetime.now(UTC).date() - timedelta(days=1)
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
