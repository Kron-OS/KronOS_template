"""Throwaway Celery entrypoint for this PoC's own verification-speed beat
schedule override (roadmap Milestone W/W1).

This imports the REAL, unmodified ``celery_app`` object (and therefore every
real task function -- ``seal_pending_streams``/``normalize_stream_batch``/
``sync_detection_findings``, plus the whole existing evidence-parsing DAG)
from ``src.external.celery_app`` verbatim. The ONLY thing this module does
is shorten two of the real ``beat_schedule`` entries' own intervals, purely
so this PoC's own real, live verification run finishes in a bounded number
of minutes rather than waiting out the full 60s/5min production cadence --
mirroring this repo's own established "short-interval override for testing
purposes" precedent (e.g. poc/celery_beat/README.md speeding up
abort_orphan_*'s hourly cadence by seeding already-stale rows instead).

No task body, no queue routing, no production `src/` file is touched or
duplicated here -- `celery -A poc.autonomous_detection_pipeline
._beat_schedule_override worker/beat` runs the exact same real Celery `App`
object `celery -A src.external.celery_app worker/beat` would, just ticking
faster.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.external.celery_app import celery_app  # noqa: E402

# Real production values (celery_app.py): 60.0 seconds / crontab(minute="*/5").
# Shortened here, for this verification run only, to keep the real,
# autonomous end-to-end proof's own wall-clock window bounded.
#
# sync-detection-findings is NOT shortened as aggressively as
# seal-pending-streams: a real, live run (worker.log, captured during this
# PoC's own hardening) showed sync_detection_findings' own real body --
# KeycloakAdminClient.list_organizations() (crosses every real org in this
# dev Keycloak realm, not just this run's own fresh one) + one
# DetectionSyncService.sync_org_findings() call per org -- consistently
# takes ~29-30s wall-clock against the real dev stack. A 15s override
# interval against a ~30s real runtime is a structural overload (arrival
# faster than service) that permanently monopolizes this PoC's own worker
# pool's slots and starves seal_pending_streams/normalize_stream_batch
# (same q.index queue as production, see celery_app.py task_routes) --
# confirmed live: normalize_stream_batch for round 2 sat RECEIVED for 50+s
# behind a backlog of these before this fix. 45s is chosen so it is
# comfortably longer than the observed ~30s real runtime (no structural
# backlog) while still far faster than production's 5-minute cadence.
celery_app.conf.beat_schedule["seal-pending-streams"]["schedule"] = 10.0
celery_app.conf.beat_schedule["sync-detection-findings"]["schedule"] = 45.0

__all__ = ["celery_app"]
