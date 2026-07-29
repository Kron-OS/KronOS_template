"""Tests for the pluggable step-up ticket stores (audit finding M-4).

Covers the in-memory store and the Redis store (via a small in-process fake
redis client), plus the cross-instance sharing that the Redis store enables and
the in-memory store does not.
"""

from __future__ import annotations

import uuid

from src.external.middleware.step_up_auth import StepUpAuth
from src.external.middleware.step_up_store import (
    _TICKET_TTL_SECONDS,
    ConsumeResult,
    InMemoryTicketStore,
    RedisTicketStore,
)


class _FakeRedis:
    """Minimal redis-py stand-in: SET (with EX) + atomic GETDEL."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.last_ex: int | None = None

    def set(self, name: str, value: str, ex: int | None = None) -> bool:
        self.store[name] = value
        self.last_ex = ex
        return True

    def getdel(self, name: str):  # type: ignore[no-untyped-def]
        return self.store.pop(name, None)


def _ids() -> tuple[uuid.UUID, str, str]:
    return uuid.uuid4(), "evidence.delete", str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Store-level parity tests (run against both implementations)
# ---------------------------------------------------------------------------


def _make_stores() -> list[tuple[str, object]]:
    return [("memory", InMemoryTicketStore()), ("redis", RedisTicketStore(_FakeRedis()))]


def test_put_then_consume_succeeds_once() -> None:
    for label, store in _make_stores():
        tid = uuid.uuid4()
        user, op, res = _ids()
        store.put(tid, user, op, res)
        assert store.consume(tid, user, op, res) is ConsumeResult.CONSUMED, label
        # Second consume must fail — single use.
        assert store.consume(tid, user, op, res) is ConsumeResult.NOT_FOUND, label


def test_unknown_ticket_is_not_found() -> None:
    for label, store in _make_stores():
        user, op, res = _ids()
        assert store.consume(uuid.uuid4(), user, op, res) is ConsumeResult.NOT_FOUND, label


def test_wrong_fields_are_mismatch() -> None:
    for label, store in _make_stores():
        tid = uuid.uuid4()
        user, op, res = _ids()
        store.put(tid, user, op, res)
        assert store.consume(tid, uuid.uuid4(), op, res) is ConsumeResult.MISMATCH, label


def test_redis_put_sets_ttl() -> None:
    fake = _FakeRedis()
    store = RedisTicketStore(fake)
    tid = uuid.uuid4()
    user, op, res = _ids()
    store.put(tid, user, op, res)
    assert fake.last_ex == _TICKET_TTL_SECONDS


def test_redis_store_decodes_bytes_values() -> None:
    """A redis client without decode_responses returns bytes; consume still works."""

    class _BytesRedis(_FakeRedis):
        def getdel(self, name: str):  # type: ignore[no-untyped-def]
            v = self.store.pop(name, None)
            return v.encode() if v is not None else None

    store = RedisTicketStore(_BytesRedis())
    tid = uuid.uuid4()
    user, op, res = _ids()
    store.put(tid, user, op, res)
    assert store.consume(tid, user, op, res) is ConsumeResult.CONSUMED


# ---------------------------------------------------------------------------
# The point of the fix: tickets are shared across instances via Redis.
# ---------------------------------------------------------------------------


def test_redis_ticket_is_valid_across_separate_instances() -> None:
    """A ticket issued on one StepUpAuth instance is consumable on another.

    Simulates two backend replicas pointed at the same Redis. This is exactly
    the M-4 scenario that the in-memory store fails.
    """
    shared = _FakeRedis()
    replica_a = StepUpAuth(store=RedisTicketStore(shared))
    replica_b = StepUpAuth(store=RedisTicketStore(shared))

    user_id = uuid.uuid4()
    resource = str(uuid.uuid4())
    ticket_id = replica_a.issue_ticket(user_id, "evidence.delete", resource)

    # Consuming on the *other* replica must succeed (no exception raised).
    replica_b.consume_ticket(ticket_id, user_id, "evidence.delete", resource)


def test_inmemory_ticket_is_not_shared_across_instances() -> None:
    """In-memory tickets are process/instance-local — documents the M-4 gap."""
    import pytest
    from fastapi import HTTPException

    replica_a = StepUpAuth(store=InMemoryTicketStore())
    replica_b = StepUpAuth(store=InMemoryTicketStore())

    user_id = uuid.uuid4()
    resource = str(uuid.uuid4())
    ticket_id = replica_a.issue_ticket(user_id, "evidence.delete", resource)

    with pytest.raises(HTTPException):
        replica_b.consume_ticket(ticket_id, user_id, "evidence.delete", resource)
