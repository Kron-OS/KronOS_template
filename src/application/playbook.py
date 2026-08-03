"""PlaybookAction: extensible, pluggable response actions (roadmap M7/H1).

Mirrors this codebase's established ABC+registry extensibility idiom
(``ForensicParser``/``ParserRegistry``, ``Enricher``/``EnrichmentPipeline``,
``CostGateHeuristic``/``RuleCostGate``): a new action is a new registration,
zero changes to ``PlaybookActionRegistry`` or ``PlaybookExecutionService``
(roadmap H1's own "new action = registration, not an edit" requirement).

**Scope boundary (binding, not a style choice).** This module and every
concrete action registered against it in THIS pass are non-destructive --
they act only on KronOS's own data (e.g. a ``Detection``'s own triage
state) or produce no side effect at all (e.g. a log entry). Real
containment actions with an external, destructive side effect (isolate a
host, block an IP, revoke a session) are roadmap H2's explicitly separate,
gated scope: "prove no destructive action can execute without either an
explicit policy authorization or human approval." Do not register a
destructive ``PlaybookAction`` against this same, ungated registry without
first building H2's approval-gate mechanism -- that is exactly the gap H2
exists to close.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from src.domain.user import TenantContext


class PlaybookAction(ABC):
    """One real, registered response action a ``Playbook`` step can invoke.

    ``execute()`` performs whatever real work this action does and returns
    a real, structured output dict describing what happened -- never a
    fabricated/placeholder result. Raising is the correct way to signal
    failure; ``PlaybookExecutionService`` is responsible for catching it,
    auditing it, and deciding whether to halt the rest of the playbook
    (this method must never audit anything itself -- that is the
    execution service's single responsibility, mirroring
    ``Enricher.enrich()``'s own "collaborator does the work, orchestrator
    does the bookkeeping" division of labor).
    """

    @property
    @abstractmethod
    def action_name(self) -> str:
        """Stable registry key referenced by ``PlaybookStep.action_name``."""

    @abstractmethod
    async def execute(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        """Run this action with *params*, scoped to *tenant*'s own org.

        *tenant* is always the authenticated caller's own ``TenantContext``
        (never anything read out of ``params``) -- roadmap invariant #3,
        applied here identically to every other tenant-scoped service in
        this codebase.
        """


class PlaybookActionRegistry:
    """Holds registered ``PlaybookAction``s, keyed by their own ``action_name``.

    Unlike ``ParserRegistry`` (first-match-wins over an unordered list, since
    parser selection is content-sniffing), a playbook step names its action
    explicitly and unambiguously -- a plain dict keyed by name is the
    correct, simpler structure here, not a premature copy of a different
    registry's own matching strategy.
    """

    def __init__(self) -> None:
        self._actions: dict[str, PlaybookAction] = {}

    def register(self, action: PlaybookAction) -> None:
        """Add *action*. A second registration under the same ``action_name``
        replaces the first -- callers that need to prevent that are
        responsible for checking ``get_action`` first; this registry only
        ever does bookkeeping, no policy."""
        self._actions[action.action_name] = action

    def get_action(self, action_name: str) -> PlaybookAction | None:
        """Return the registered action for *action_name*, or ``None`` if
        none is registered -- an honest absence
        ``PlaybookExecutionService`` treats as a real step failure, never
        silently skipped."""
        return self._actions.get(action_name)
