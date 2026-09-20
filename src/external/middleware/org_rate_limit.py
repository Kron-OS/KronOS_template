"""Minimal per-org rate limiter for admin mutation routes.

No rate-limiting middleware exists anywhere else in this codebase
(confirmed by grep before writing this) -- deliberately NOT a
platform-wide effort here, just a small guard scoped to the connector
marketplace's config-mutation routes (``admin_connector_config.py``),
which write to both Postgres and Vault per call. Step-up (aal2) already
gates who can call these routes; this bounds how often even a valid,
authenticated admin session can call them, so a compromised/scripted
session can't hammer Vault/Postgres with rapid repeated writes.

Fixed token bucket per (org_id, bucket_name), in-process only (matches
``StepUpTicketStore``'s own in-memory default -- acceptable here since a
restart merely resets everyone's budget, not a security hole).
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict

from fastapi import HTTPException, status


class OrgRateLimiter:
    """Thread-unsafe in-memory token bucket, keyed per (org_id, bucket_name)."""

    def __init__(self, *, max_requests: int, window_seconds: float) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._hits: dict[tuple[uuid.UUID, str], list[float]] = defaultdict(list)

    def check(self, org_id: uuid.UUID, bucket_name: str) -> None:
        """Raise HTTP 429 if *org_id* has exceeded the budget for *bucket_name*."""
        now = time.monotonic()
        key = (org_id, bucket_name)
        window_start = now - self._window_seconds
        recent = [t for t in self._hits[key] if t >= window_start]
        if len(recent) >= self._max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Rate limit exceeded: max {self._max_requests} requests per "
                    f"{self._window_seconds:.0f}s for this operation"
                ),
            )
        recent.append(now)
        self._hits[key] = recent


# Shared instance for connector-config mutation routes -- 20 mutating calls
# per org per minute is generous for a human admin, tight enough to bound a
# scripted/compromised session hammering Vault/Postgres.
connector_config_rate_limiter = OrgRateLimiter(max_requests=20, window_seconds=60.0)
