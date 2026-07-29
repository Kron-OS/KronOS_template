"""Pluggable backing store for one-time step-up tickets.

``InMemoryTicketStore`` keeps tickets in a per-process dict (fine for a single
worker / single replica). ``RedisTicketStore`` keeps them in Redis so that a
ticket issued by one backend instance can be consumed by another — required for
the multi-replica deployments in docker-compose.prod.yml and the Helm chart
(audit finding M-4).

Both stores guarantee a ticket can be successfully consumed at most once.
"""

from __future__ import annotations

import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, auto
from typing import Any, Protocol

_TICKET_TTL_SECONDS = 300  # 5 minutes


class ConsumeResult(Enum):
    """Outcome of attempting to consume a ticket."""

    CONSUMED = auto()  # ticket existed, matched, and is now spent
    NOT_FOUND = auto()  # ticket missing, expired, or already used
    MISMATCH = auto()  # ticket existed but user/operation/resource differ


class TicketStore(ABC):
    """Stores one-time step-up tickets keyed by ticket id."""

    @abstractmethod
    def put(
        self, ticket_id: uuid.UUID, user_id: uuid.UUID, operation: str, resource_id: str
    ) -> None:
        """Persist a new ticket with the configured TTL."""

    @abstractmethod
    def consume(
        self, ticket_id: uuid.UUID, user_id: uuid.UUID, operation: str, resource_id: str
    ) -> ConsumeResult:
        """Atomically validate and spend a ticket; return the outcome."""


# ---------------------------------------------------------------------------
# In-memory implementation (single process)
# ---------------------------------------------------------------------------


@dataclass
class _Ticket:
    user_id: uuid.UUID
    operation: str
    resource_id: str
    issued_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    used: bool = False


class InMemoryTicketStore(TicketStore):
    """Process-local ticket store. Not safe across workers/replicas."""

    def __init__(self, ttl_seconds: int = _TICKET_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._tickets: dict[uuid.UUID, _Ticket] = {}
        self._lock = threading.Lock()

    def put(
        self, ticket_id: uuid.UUID, user_id: uuid.UUID, operation: str, resource_id: str
    ) -> None:
        with self._lock:
            self._purge_expired()
            self._tickets[ticket_id] = _Ticket(
                user_id=user_id, operation=operation, resource_id=resource_id
            )

    def consume(
        self, ticket_id: uuid.UUID, user_id: uuid.UUID, operation: str, resource_id: str
    ) -> ConsumeResult:
        with self._lock:
            self._purge_expired()
            ticket = self._tickets.get(ticket_id)
            if ticket is None or ticket.used:
                return ConsumeResult.NOT_FOUND
            if (
                ticket.user_id != user_id
                or ticket.operation != operation
                or ticket.resource_id != resource_id
            ):
                return ConsumeResult.MISMATCH
            ticket.used = True
            return ConsumeResult.CONSUMED

    def _purge_expired(self) -> None:
        now = datetime.now(UTC)
        expired = [
            tid
            for tid, t in self._tickets.items()
            if (now - t.issued_at).total_seconds() > self._ttl
        ]
        for tid in expired:
            del self._tickets[tid]


# ---------------------------------------------------------------------------
# Redis implementation (shared across workers/replicas)
# ---------------------------------------------------------------------------


class _RedisLike(Protocol):
    """Subset of the redis-py client used by RedisTicketStore."""

    def set(self, name: str, value: str, ex: int | None = ...) -> Any: ...

    def getdel(self, name: str) -> Any: ...


class RedisTicketStore(TicketStore):
    """Redis-backed ticket store providing cross-instance single-use semantics.

    ``put`` writes ``user|operation|resource`` under ``kronos:stepup:<id>`` with
    a TTL so expired tickets vanish automatically. ``consume`` uses ``GETDEL``,
    which atomically returns and removes the value in one round-trip — so a
    ticket can be spent exactly once even when several replicas race. The match
    check is performed after the atomic delete: any presentation of a ticket
    spends it (fail-closed), which is at least as strict as the in-memory store.
    """

    _PREFIX = "kronos:stepup:"

    def __init__(self, client: _RedisLike, ttl_seconds: int = _TICKET_TTL_SECONDS) -> None:
        self._client = client
        self._ttl = ttl_seconds

    @staticmethod
    def _value(user_id: uuid.UUID, operation: str, resource_id: str) -> str:
        return f"{user_id}|{operation}|{resource_id}"

    def put(
        self, ticket_id: uuid.UUID, user_id: uuid.UUID, operation: str, resource_id: str
    ) -> None:
        self._client.set(
            self._PREFIX + str(ticket_id),
            self._value(user_id, operation, resource_id),
            ex=self._ttl,
        )

    def consume(
        self, ticket_id: uuid.UUID, user_id: uuid.UUID, operation: str, resource_id: str
    ) -> ConsumeResult:
        stored = self._client.getdel(self._PREFIX + str(ticket_id))
        if stored is None:
            return ConsumeResult.NOT_FOUND
        if isinstance(stored, bytes):
            stored = stored.decode("utf-8")
        expected = self._value(user_id, operation, resource_id)
        return ConsumeResult.CONSUMED if stored == expected else ConsumeResult.MISMATCH
