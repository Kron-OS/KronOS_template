"""SealerLagCalculator: surfaces D1/D3/D5's own already-real backlog/lag
primitives as a queryable per-org metric (roadmap M8/I2).

Deliberately does NOT reimplement lag computation -- ``StreamIngestAdapter
.consumer_group_health()`` (``src/adapter/queue/stream_ingest.py``) already
returns real ``pending_count``/``lag`` from Redis Streams' own
``XPENDING``/``XINFO GROUPS`` primitives, and ``BatchSealingService``
already uses the identical (org, source, "kronos-sealer") triple as its own
liveness signal (``_check_sealer_fall_behind``). This calculator's only
real job is enumerating which sources belong to this org
(``SealedBatchRepository.list_source_ids_for_org``, added alongside this
item) and aggregating the per-source health snapshots into one
``MetricResult``.

**A real, load-bearing finding from building this against the live dev
stack (see ``poc/metrics_kpis/output.txt``): Redis had zero stream keys at
all** at the time this was built -- the D1-D5 session's own real Redis
Streams data does not persist (no AOF/RDB durability configured for the
dev compose Redis, and/or a restart since). This is structurally different
from Postgres's ``sealed_batches`` table, which IS durable (WORM-backed,
per roadmap M3/D3) -- so `SealerLagCalculator` can always enumerate real
historical sources and their last-seal timestamps, but a **live**
``pending_count``/``lag`` reading is only meaningful for a source whose
Redis consumer group still exists. When it doesn't, this calculator
reports that honestly (``live_group_found: false`` per source) rather than
fabricating a zero -- a stream with no live consumer group is NOT the same
fact as "zero backlog", it is "we cannot currently observe this source's
live backlog at all".
"""

from __future__ import annotations

from typing import Any

from src.adapter.queue.stream_ingest import StreamIngestAdapter
from src.adapter.repository.sealed_batch import SealedBatchRepository
from src.application.metric_calculator import MetricCalculator
from src.domain.metrics import MetricResult
from src.domain.user import TenantContext

# Matches BatchSealingService's own default `consumer_group` constructor
# argument (src/application/batch_sealing.py) -- the well-known name every
# real sealer instance in this deployment consumes under, unless a caller
# explicitly overrides it (not done anywhere in this codebase today).
_DEFAULT_SEALER_GROUP = "kronos-sealer"


class SealerLagCalculator(MetricCalculator):
    """Aggregated real consumer-group backlog across this org's sealed sources."""

    def __init__(
        self,
        sealed_batch_repository: SealedBatchRepository,
        stream_adapter: StreamIngestAdapter,
        consumer_group: str = _DEFAULT_SEALER_GROUP,
    ) -> None:
        self._sealed_batches = sealed_batch_repository
        self._stream = stream_adapter
        self._group = consumer_group

    @property
    def metric_name(self) -> str:
        return "sealer_lag_pending_messages"

    async def compute(self, tenant: TenantContext) -> MetricResult:
        source_ids = await self._sealed_batches.list_source_ids_for_org(tenant.org_id)
        if not source_ids:
            return MetricResult(
                metric_name=self.metric_name,
                org_id=tenant.org_id,
                value=None,
                unit="messages",
                sample_size=0,
                detail={},
                unavailable_reason="This org has never sealed a batch -- no sources to check.",
            )

        per_source: dict[str, dict[str, Any]] = {}
        live_backlog_total = 0
        live_group_count = 0
        for source_id in source_ids:
            health = await self._stream.consumer_group_health(tenant.org_id, source_id, self._group)
            last_sealed = await self._sealed_batches.get_last_sealed(tenant.org_id, source_id)
            live_found = health.lag is not None
            # Both pending_count (delivered, never acked -- a stuck/crashed
            # sealer) and lag (never delivered to any consumer -- no sealer
            # running at all) are real, distinct ways a source can have
            # unsealed backlog (see ConsumerGroupHealth's own docstring).
            # Summing them, not reporting pending_count alone, matters: a
            # source whose sealer process isn't running at all has
            # pending_count == 0 (nothing was ever delivered to get stuck)
            # but a real, growing lag -- reporting pending_count alone would
            # silently show "0" for the single worst failure mode this
            # metric exists to catch.
            backlog = (health.pending_count if live_found else 0) + (health.lag or 0)
            per_source[source_id] = {
                "live_group_found": live_found,
                "pending_count": health.pending_count if live_found else None,
                "lag": health.lag,
                "backlog": backlog if live_found else None,
                "last_sealed_at": last_sealed.sealed_at.isoformat() if last_sealed else None,
            }
            if live_found:
                live_group_count += 1
                live_backlog_total += backlog

        if live_group_count == 0:
            return MetricResult(
                metric_name=self.metric_name,
                org_id=tenant.org_id,
                value=None,
                unit="messages",
                sample_size=0,
                detail={"per_source": per_source, "sources_checked": len(source_ids)},
                unavailable_reason=(
                    f"No live Redis consumer group ('{self._group}') found for any of "
                    f"this org's {len(source_ids)} known source(s) -- their streams have "
                    "likely already been fully drained/cleared since their last real "
                    "seal (see last_sealed_at per source in detail for staleness "
                    "instead of live backlog)."
                ),
            )

        return MetricResult(
            metric_name=self.metric_name,
            org_id=tenant.org_id,
            value=float(live_backlog_total),
            unit="messages",
            sample_size=live_group_count,
            detail={"per_source": per_source, "sources_checked": len(source_ids)},
        )
