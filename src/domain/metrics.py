"""MetricResult domain model: the result of computing one KPI, always
honest about whether it could actually be computed.

Roadmap M8/I2 (docs/NEXTGEN_SOC_ROADMAP.md). Mirrors ``CostGateVerdict``'s
own shape (a small, frozen Pydantic value object returned by an
application-layer service, not a raw dict) and roadmap invariant #8
("fail loudly, never silently"): ``value`` is ``None`` -- never a
fabricated ``0.0``/``100.0`` -- whenever the real data this metric needs
genuinely does not exist yet for this org, with ``unavailable_reason``
stating why in plain language a human can act on.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class MetricResult(BaseModel):
    """One computed (or honestly-not-yet-computable) KPI value."""

    model_config = {"frozen": True}

    metric_name: str
    # None ONLY for a genuinely cross-org/system-wide metric (roadmap
    # invariant #3's own carve-out, e.g. an ops-facing sealer-lag rollup
    # across every org for an operator role) -- every per-org
    # MetricCalculator MUST set this from the caller's own
    # TenantContext.org_id, never from anything read out of the
    # underlying data it queried.
    org_id: uuid.UUID | None
    computed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    value: float | None
    unit: str
    # How many real underlying data points (Detections, audit rows,
    # sources, ...) fed this computation -- lets a caller distinguish
    # "0.0 computed from 500 samples" from "0.0 computed from 1 sample",
    # which a bare float can never do on its own.
    sample_size: int
    detail: dict[str, Any] = Field(default_factory=dict)
    unavailable_reason: str | None = None

    @property
    def is_available(self) -> bool:
        return self.value is not None
