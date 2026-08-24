"""KeycloakAdminClient: real Admin REST API operations against Keycloak
26.2 (roadmap M7/H2's real containment target -- see
``poc/containment_approval_gate/README.md`` for why session revocation,
not "block IP"/"isolate host" -- the roadmap's other two named examples --
is the one containment action this pass ships with a genuinely real,
destructive backend in this repo's actual dev stack).

Uses the already-provisioned ``kronos-backend`` confidential client's own
service account (``docker/keycloak/kronos-realm.json`` already grants it
realm-management ``manage-users``/``view-users`` -- AUTH-001, "scoped to
manage-users/view-users/manage-realm/view-realm only... never grant
realm-admin") -- same admin-credentials trust tier as
``SecurityAnalyticsDetectorProvisioner``'s OpenSearch admin credentials
(the A3 gate's own binding condition, applied here to Keycloak instead of
OpenSearch).

Every response shape below (204 on real session revocation, 404 with the
literal upstream body ``{"error":"Sesssion not found"}`` -- note Keycloak
26.2's own typo, reproduced verbatim, not a transcription error here -- on
an already-gone session, 200/404 on the org-membership check) was
confirmed against the real, live Keycloak 26.2.5 container
(``docker-keycloak-1``) before this file was written -- see
``poc/containment_approval_gate/output.txt``.

**Organizations lookups (``get_organization_alias``/``list_organizations``,
roadmap Milestone W/W1)** were added later, for a different real problem:
Celery beat tasks that discover an ``org_id`` from something other than an
authenticated JWT (e.g. a Redis stream key, per
``StreamIngestAdapter.list_active_streams()``) have no ``TenantContext`` to
read ``org_alias`` off of -- the JWT's own ``organization`` claim
(``src/external/middleware/keycloak_auth.py::_extract_tenant``) is the
*only* other place ``org_alias`` is ever resolved in this codebase, and it
does not exist without a request. Keycloak Organizations is this
platform's own explicit source of truth for tenant identity (CLAUDE.md
"Key Decisions: Keycloak 26+ Organizations for multi-tenancy"), so a real
Admin API lookup here -- not a second, drifting local copy -- is the
correct fix. Both new methods' exact response shapes (200 with a real
``alias`` field, 404 ``{"errorMessage":"Organization not found."}``) were
confirmed live against ``docker-keycloak-1`` using the same
``kronos-backend`` service-account credentials ``HttpxKeycloakAdminClient``
already authenticates with for ``is_org_member`` above -- see
``poc/autonomous_detection_pipeline/README.md``.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from src.exceptions import KeycloakAdminError

_TOKEN_REFRESH_MARGIN_SECONDS = 10


@dataclass(frozen=True)
class KeycloakSession:
    """The fields of a real Keycloak ``UserSessionRepresentation`` this
    adapter's callers actually need -- not a full mirror of every field
    Keycloak returns (mirrors ``DetectionRuleMatch``'s own "only what's
    replayed" idiom)."""

    session_id: str
    user_id: str
    username: str
    ip_address: str
    started_at_epoch_ms: int


@dataclass(frozen=True)
class KeycloakOrganization:
    """The fields of a real Keycloak ``OrganizationRepresentation`` a beat
    task actually needs -- ``org_id``/``alias`` are the only two fields
    ``sync_org_findings``'s per-task ``TenantContext`` construction and
    stream-index naming (``build_stream_index_name``) ever read."""

    org_id: uuid.UUID
    alias: str


class KeycloakAdminClient(ABC):
    """Real Keycloak Admin REST API operations this platform needs for
    containment. New operations = new abstract methods here (small,
    intentionally not a generic HTTP passthrough) -- keeps every
    containment adapter's real backend calls typed and centrally mockable
    in unit tests, per CLAUDE.md SS B.5."""

    @abstractmethod
    async def list_user_sessions(self, user_id: uuid.UUID) -> tuple[KeycloakSession, ...]:
        """Real, live sessions for *user_id* right now."""

    @abstractmethod
    async def revoke_session(self, session_id: str) -> None:
        """Destructively terminate one real session.

        Raises ``KeycloakAdminError`` if the real backend is unreachable or
        rejects the call for any reason other than the session already
        being gone -- never a silent no-op (CLAUDE.md SS1#8).
        """

    @abstractmethod
    async def is_org_member(self, org_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Real, live membership check -- never trust a caller-supplied claim
        that a user belongs to a given org (roadmap invariant #3)."""

    @abstractmethod
    async def get_organization_alias(self, org_id: uuid.UUID) -> str | None:
        """Real, live ``alias`` for *org_id*, or ``None`` if no such
        organization exists (roadmap Milestone W/W1) -- see this class's own
        module docstring for why a Celery beat task needs this at all."""

    @abstractmethod
    async def list_organizations(self) -> tuple[KeycloakOrganization, ...]:
        """Every real organization in this realm right now (roadmap
        Milestone W/W1) -- Keycloak Organizations is this platform's own
        tenant registry (CLAUDE.md "Key Decisions"), so this is the
        authoritative "list every real tenant" primitive a beat task needs
        to discover which orgs to do per-org work for, without inventing a
        second, locally-drifting tenant list."""


class HttpxKeycloakAdminClient(KeycloakAdminClient):
    """Real implementation: client-credentials grant against the
    already-provisioned ``kronos-backend`` confidential client, then the
    real Admin REST API. Verified live against Keycloak 26.2.5
    (``docker-keycloak-1``) -- see ``poc/containment_approval_gate/``.
    """

    def __init__(
        self,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        *,
        verify: bool | str = True,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._realm = realm
        self._client_id = client_id
        self._client_secret = client_secret
        self._verify = verify
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    async def _admin_token(self, client: httpx.AsyncClient) -> str:
        if self._token is not None and time.monotonic() < self._token_expires_at:
            return self._token
        try:
            resp = await client.post(
                f"{self._base_url}/realms/{self._realm}/protocol/openid-connect/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise KeycloakAdminError(
                "Failed to obtain Keycloak admin token", context={"error": str(exc)}
            ) from exc
        body = resp.json()
        self._token = body["access_token"]
        self._token_expires_at = (
            time.monotonic() + body.get("expires_in", 60) - _TOKEN_REFRESH_MARGIN_SECONDS
        )
        return self._token

    async def _admin_request(self, method: str, path: str) -> httpx.Response:
        async with httpx.AsyncClient(timeout=15, verify=self._verify) as client:
            token = await self._admin_token(client)
            try:
                return await client.request(
                    method,
                    f"{self._base_url}/admin/realms/{self._realm}{path}",
                    headers={"Authorization": f"Bearer {token}"},
                )
            except httpx.HTTPError as exc:
                raise KeycloakAdminError(
                    f"Keycloak admin request failed: {method} {path}",
                    context={"error": str(exc)},
                ) from exc

    async def list_user_sessions(self, user_id: uuid.UUID) -> tuple[KeycloakSession, ...]:
        resp = await self._admin_request("GET", f"/users/{user_id}/sessions")
        if resp.status_code != 200:
            raise KeycloakAdminError(
                "Failed to list Keycloak user sessions",
                context={"user_id": str(user_id), "status": resp.status_code, "body": resp.text},
            )
        sessions: list[KeycloakSession] = []
        for s in resp.json():
            try:
                sessions.append(
                    KeycloakSession(
                        session_id=s["id"],
                        user_id=s["userId"],
                        username=s["username"],
                        ip_address=s.get("ipAddress", ""),
                        started_at_epoch_ms=s.get("start", 0),
                    )
                )
            except KeyError as exc:
                # Gap Audit Milestone VV: mirrors list_organizations()'s own
                # defensive parsing (that method already raises a clean
                # KeycloakAdminError on a missing id/alias, this sibling
                # "iterate an admin API list response" method did not) -- a
                # real session entry always has id/userId/username
                # (confirmed live), so a missing one is a genuinely
                # unexpected upstream shape worth failing loudly on, not a
                # raw KeyError escaping into an unhelpful audit-log message.
                raise KeycloakAdminError(
                    "Keycloak session list entry missing required field",
                    context={"user_id": str(user_id), "entry": s, "error": str(exc)},
                ) from exc
        return tuple(sessions)

    async def revoke_session(self, session_id: str) -> None:
        resp = await self._admin_request("DELETE", f"/sessions/{session_id}")
        # Real, confirmed Keycloak 26.2.5 shape: 204 on genuine revocation,
        # 404 when the session id is already gone/never existed -- both are
        # legitimate terminal outcomes for "this session is not live," so
        # neither is a KronOS-side failure. Any OTHER status (401/403/5xx)
        # is a real backend problem and must fail loudly, never be treated
        # as an implicit success.
        if resp.status_code not in (204, 404):
            raise KeycloakAdminError(
                "Failed to revoke Keycloak session",
                context={"session_id": session_id, "status": resp.status_code, "body": resp.text},
            )

    async def is_org_member(self, org_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        resp = await self._admin_request("GET", f"/organizations/{org_id}/members/{user_id}")
        if resp.status_code == 200:
            return True
        if resp.status_code == 404:
            return False
        raise KeycloakAdminError(
            "Failed to check Keycloak org membership",
            context={"org_id": str(org_id), "user_id": str(user_id), "status": resp.status_code},
        )

    async def get_organization_alias(self, org_id: uuid.UUID) -> str | None:
        resp = await self._admin_request("GET", f"/organizations/{org_id}")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise KeycloakAdminError(
                "Failed to fetch Keycloak organization",
                context={"org_id": str(org_id), "status": resp.status_code, "body": resp.text},
            )
        body = resp.json()
        alias = body.get("alias")
        if not alias:
            # Real Keycloak 26.2 always returns a non-empty alias for a real
            # org (confirmed live) -- an empty/missing one on a 200 response
            # is a genuinely unexpected upstream shape, not a "no org"
            # outcome, so this must not be silently treated the same as 404.
            raise KeycloakAdminError(
                "Keycloak organization response has no alias",
                context={"org_id": str(org_id), "body": resp.text},
            )
        return str(alias)

    async def list_organizations(self) -> tuple[KeycloakOrganization, ...]:
        resp = await self._admin_request("GET", "/organizations")
        if resp.status_code != 200:
            raise KeycloakAdminError(
                "Failed to list Keycloak organizations",
                context={"status": resp.status_code, "body": resp.text},
            )
        organizations: list[KeycloakOrganization] = []
        for org in resp.json():
            try:
                organizations.append(
                    KeycloakOrganization(org_id=uuid.UUID(org["id"]), alias=org["alias"])
                )
            except (KeyError, ValueError) as exc:
                raise KeycloakAdminError(
                    "Keycloak organization list entry missing/malformed id or alias",
                    context={"entry": org, "error": str(exc)},
                ) from exc
        return tuple(organizations)
