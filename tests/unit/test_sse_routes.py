"""Unit tests for SSE ticket and stream routes."""

from __future__ import annotations

import asyncio
import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from src.adapter.repository.case_repository import InMemoryCaseRepository
from src.domain.case import Case, CaseMetadata
from src.domain.evidence import Evidence, EvidenceState
from src.domain.user import Role, TenantContext
from src.external.dependencies import (
    get_case_repository,
    get_evidence_repository,
    get_tenant_context,
)
from src.external.fastapi_app import create_app
from src.external.routes import sse as sse_module
from tests.conftest import InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence_metadata


@pytest.fixture(autouse=True)
def clear_tickets():
    """Clear the in-memory ticket store between tests."""
    sse_module._tickets.clear()
    yield
    sse_module._tickets.clear()


@pytest.fixture
def sse_client():
    fixed_org = uuid.uuid4()
    fixed_user = uuid.uuid4()

    def _fixed_tenant() -> TenantContext:
        return TenantContext(
            org_id=fixed_org,
            org_alias="testorg",
            user_id=fixed_user,
            username="tester",
            roles=frozenset({Role.ANALYST}),
            correlation_id=str(uuid.uuid4()),
        )

    evidence_repo = InMemoryEvidenceRepository()
    case_repo = InMemoryCaseRepository()
    app = create_app()
    app.dependency_overrides[get_tenant_context] = _fixed_tenant
    app.dependency_overrides[get_evidence_repository] = lambda: evidence_repo
    app.dependency_overrides[get_case_repository] = lambda: case_repo
    return TestClient(app), fixed_org, fixed_user, evidence_repo, case_repo


class TestCreateSSETicket:
    """Fixed 2026-08-15 (Task #14 security/red-team assessment, P1-SEC-1):
    create_sse_ticket now requires the caller to have real case-level access
    (case exists, belongs to their org, and they own/are a member of it --
    or are org-admin) before minting a ticket -- mirrors cases.py's own
    get_by_id + assert_case_access pattern. Every test below seeds a real,
    access-granted case first; the two new tests at the bottom prove the
    fix itself (case not found -> 404; real case, caller not a member,
    not org-admin -> 403)."""

    def test_creates_ticket(self, sse_client):
        client, org_id, user_id, _, case_repo = sse_client
        case = asyncio.run(
            case_repo.save(
                Case(
                    org_id=org_id,
                    org_alias="testorg",
                    owner_user_id=user_id,
                    metadata=CaseMetadata(title="t", description="d", reference_number="C-1"),
                )
            )
        )
        resp = client.post("/api/sse/ticket", json={"caseId": str(case.case_id)})
        assert resp.status_code == 201
        data = resp.json()
        assert "ticket" in data
        assert data["expiresIn"] == 60
        assert data["ticket"] in sse_module._tickets

    def test_ticket_is_scoped_to_case(self, sse_client):
        client, org_id, user_id, _, case_repo = sse_client
        case = asyncio.run(
            case_repo.save(
                Case(
                    org_id=org_id,
                    org_alias="testorg",
                    owner_user_id=user_id,
                    metadata=CaseMetadata(title="t", description="d", reference_number="C-1"),
                )
            )
        )
        resp = client.post("/api/sse/ticket", json={"caseId": str(case.case_id)})
        ticket = resp.json()["ticket"]
        assert sse_module._tickets[ticket]["case_id"] == str(case.case_id)

    def test_ticket_is_scoped_to_org(self, sse_client):
        client, org_id, user_id, _, case_repo = sse_client
        case = asyncio.run(
            case_repo.save(
                Case(
                    org_id=org_id,
                    org_alias="testorg",
                    owner_user_id=user_id,
                    metadata=CaseMetadata(title="t", description="d", reference_number="C-1"),
                )
            )
        )
        resp = client.post("/api/sse/ticket", json={"caseId": str(case.case_id)})
        ticket = resp.json()["ticket"]
        assert sse_module._tickets[ticket]["org_id"] == str(org_id)

    def test_nonexistent_case_returns_404(self, sse_client):
        """Real proof of the fix: no case seeded at all -- must not mint a ticket."""
        client, _, _, _, _ = sse_client
        resp = client.post("/api/sse/ticket", json={"caseId": str(uuid.uuid4())})
        assert resp.status_code == 404
        assert sse_module._tickets == {}

    def test_case_caller_is_not_a_member_of_returns_403(self, sse_client):
        """Real proof of the fix (P1-SEC-1): a real case in the caller's own
        org, but the caller is neither its owner nor a listed member and
        holds no org-admin role -- must not mint a ticket for it."""
        client, org_id, _, _, case_repo = sse_client
        other_owner = uuid.uuid4()
        case = asyncio.run(
            case_repo.save(
                Case(
                    org_id=org_id,
                    org_alias="testorg",
                    owner_user_id=other_owner,
                    metadata=CaseMetadata(title="t", description="d", reference_number="C-2"),
                )
            )
        )
        resp = client.post("/api/sse/ticket", json={"caseId": str(case.case_id)})
        assert resp.status_code == 403
        assert sse_module._tickets == {}


class TestSSEStream:
    def test_expired_ticket_returns_401(self, sse_client):
        client, _, _, _, _ = sse_client
        case_id = uuid.uuid4()
        ticket = str(uuid.uuid4())
        # Insert an already-expired ticket
        sse_module._tickets[ticket] = {
            "case_id": str(case_id),
            "org_id": str(uuid.uuid4()),
            "expires": time.time() - 1,
        }
        resp = client.get(
            f"/api/sse/cases/{case_id}/evidence?ticket={ticket}",
            headers={"Accept": "text/event-stream"},
        )
        assert resp.status_code == 401

    def test_wrong_case_id_returns_401(self, sse_client):
        client, org_id, _, _, _ = sse_client
        case_id = uuid.uuid4()
        wrong_case = uuid.uuid4()
        ticket = str(uuid.uuid4())
        sse_module._tickets[ticket] = {
            "case_id": str(wrong_case),
            "org_id": str(org_id),
            "expires": time.time() + 60,
        }
        resp = client.get(
            f"/api/sse/cases/{case_id}/evidence?ticket={ticket}",
            headers={"Accept": "text/event-stream"},
        )
        assert resp.status_code == 401

    def test_missing_ticket_returns_401(self, sse_client):
        client, _, _, _, _ = sse_client
        case_id = uuid.uuid4()
        resp = client.get(
            f"/api/sse/cases/{case_id}/evidence?ticket=nonexistent",
            headers={"Accept": "text/event-stream"},
        )
        assert resp.status_code == 401

    def test_valid_ticket_consumed_once(self, sse_client, monkeypatch):
        client, org_id, _, evidence_repo, _ = sse_client
        case_id = uuid.uuid4()
        ticket = str(uuid.uuid4())
        sse_module._tickets[ticket] = {
            "case_id": str(case_id),
            "org_id": str(org_id),
            "expires": time.time() + 60,
        }
        # Real, reproduced finding (this was the ~300s slow test flagged in
        # docs/NEXTGEN_SOC_ROADMAP.md I3): this test previously seeded NO
        # evidence for the case, so evidence_repo.stream_by_case always
        # yielded nothing every poll. src/external/routes/sse.py's own
        # early-exit ("stop once all evidence is terminal") is
        # `if current and all(s in _TERMINAL_STATES for s in current.values())`
        # -- `current` truthy is False for an empty dict, so that check
        # never fired, and the generator ran the real, unmocked
        # `asyncio.sleep(_POLL_INTERVAL_SECONDS)` every iteration until the
        # real 300s `_MAX_STREAM_SECONDS` ceiling. Confirmed by
        # reproduction: `timeout 15 pytest ...::test_valid_ticket_consumed_once`
        # reliably timed out (exit 143) before this fix.
        #
        # Fix: seed one evidence item already in a terminal state (COMPLETE)
        # for this exact case_id/org_id, so the FIRST poll iteration already
        # satisfies the early-exit and the generator returns immediately
        # without ever sleeping -- this exercises the endpoint's real,
        # documented "stream closes ... when all evidence reaches a
        # terminal state" behavior instead of sidestepping it.
        #
        # Gap Audit Milestone FFFF: the early-exit above is now
        # deliberately NEVER allowed to fire on a connection's first
        # observation (see sse.py's own `first_iteration` comment -- a
        # real, reproduced race where a `kronos:sse-reconnect`'d stream's
        # first poll could still see the pre-retry terminal ERROR and
        # close itself before ever observing the retry's real recovery).
        # That means this specific evidence (terminal from the very start,
        # no in-flight retry) now needs a genuine SECOND poll cycle before
        # the generator returns -- `_POLL_INTERVAL_SECONDS` (5s real
        # seconds) is patched down here so this still respects this
        # project's own <5s-per-suite unit test budget (CLAUDE.md B.6)
        # rather than reintroducing a real sleep.
        monkeypatch.setattr(sse_module, "_POLL_INTERVAL_SECONDS", 0.01)
        asyncio.run(
            evidence_repo.save(
                Evidence(
                    metadata=make_evidence_metadata(org_id=org_id, case_id=case_id),
                    state=EvidenceState.COMPLETE,
                )
            )
        )
        # First call should consume the ticket (ticket removed from dict)
        assert ticket in sse_module._tickets
        client.get(
            f"/api/sse/cases/{case_id}/evidence?ticket={ticket}",
            headers={"Accept": "text/event-stream"},
        )
        assert ticket not in sse_module._tickets

    def test_does_not_close_on_first_observation_even_if_already_terminal(
        self, sse_client, monkeypatch
    ):
        """Gap Audit Milestone FFFF: real, reproduced race (confirmed live via
        frontend/e2e/evidence-intake-retry-dev-stack.spec.ts against the real
        dev stack, cross-checked against real celery-worker logs and a
        captured Playwright trace). `useEvidenceSSE.ts`'s `kronos:sse-reconnect`
        opens a BRAND NEW stream (fresh `last_states = {}`) the instant a
        retry-intake/retry-parse mutation's HTTP response lands -- but the
        retried Celery task can genuinely not have made its first
        state-changing write yet by the time this new connection's first
        poll runs (observed live: the reconnect's own SSE GET landed while
        `process_intake`'s retried task was still mid-dispatch). Before the
        fix, the "stop once terminal" check ran on that very first
        observation, saw the still-ERROR state, concluded nothing was left
        to watch, sent `done`, and closed permanently -- even though the
        evidence went on to genuinely reach COMPLETE ~2.4s later with
        nothing left listening (`done`, unlike `onerror`, never starts the
        client's polling fallback).

        This directly exercises `event_generator()`'s real, unmocked
        control flow (not a description of intent) via a small
        `EvidenceRepository` double whose `stream_by_case` returns a
        different real state on each successive call -- ERROR first (as if
        this connection just reconnected onto an evidence row a retry
        hasn't touched yet), then COMPLETE (the retry landing one poll
        cycle later) -- asserting the stream emits BOTH status events
        (proving it kept watching past the first, still-terminal
        observation) before finally closing.
        """
        client, org_id, _, _, _ = sse_client
        case_id = uuid.uuid4()
        evidence_id = uuid.uuid4()
        ticket = str(uuid.uuid4())
        sse_module._tickets[ticket] = {
            "case_id": str(case_id),
            "org_id": str(org_id),
            "expires": time.time() + 60,
        }
        monkeypatch.setattr(sse_module, "_POLL_INTERVAL_SECONDS", 0.01)

        metadata = make_evidence_metadata(org_id=org_id, case_id=case_id)
        states = [EvidenceState.ERROR, EvidenceState.COMPLETE]

        class _SequencedEvidenceRepo:
            """Returns a different real state on each successive poll --
            simulates a retry landing one poll cycle after this connection
            opened, without any real sleeping/threading."""

            def __init__(self) -> None:
                self.calls = 0

            async def stream_by_case(self, case_id, org_id):  # noqa: ANN001, ARG002
                idx = min(self.calls, len(states) - 1)
                self.calls += 1
                yield Evidence(evidence_id=evidence_id, metadata=metadata, state=states[idx])

        app = client.app
        app.dependency_overrides[get_evidence_repository] = _SequencedEvidenceRepo

        resp = client.get(
            f"/api/sse/cases/{case_id}/evidence?ticket={ticket}",
            headers={"Accept": "text/event-stream"},
        )
        body = resp.text
        error_payload = json.dumps({"evidenceId": str(evidence_id), "state": "ERROR"})
        complete_payload = json.dumps({"evidenceId": str(evidence_id), "state": "COMPLETE"})
        assert f"data: {error_payload}" in body, body
        assert f"data: {complete_payload}" in body, body
        assert "event: done" in body
