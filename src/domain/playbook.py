"""Playbook domain model: declarative response-automation definitions as
data, and the immutable record of one real execution (roadmap M7/H1).

**Declarative, not code.** A ``Playbook`` is a named, ordered sequence of
``PlaybookStep``s -- each step is only an ``action_name`` (a
``PlaybookActionRegistry`` key, see ``src/application/playbook.py``) plus a
``params`` dict, never Python control flow. Mirrors how ``RulePack``/
``CustomRule`` (``src/domain/rule_pack.py``) treat rule content as pure,
inspectable data rather than code -- a new playbook is authored data, never
a new class.

**Deterministic and fully audited (roadmap H1's own binding requirement).**
``PlaybookStepResult`` records enough about one step's real execution
(the action name, the exact params it ran with, its outcome, its real
output or error) to fully reconstruct what happened from the audit trail
alone, without needing anything external -- the same "explainable"
contract G3 already gated for the analytics milestone
(``docs/NEXTGEN_SOC_ROADMAP.md`` G3 STATUS note), applied here to response
actions. ``PlaybookExecutionResult`` is the full, replayable trace of one
real run.

Zero framework imports (CLAUDE.md SS A.3) -- pure Pydantic, no FastAPI/
httpx/SQLAlchemy here. Executing a playbook (real I/O, real audit calls) is
``PlaybookExecutionService``'s job (``src/application/playbook_execution.py``),
not this module's.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PlaybookStep(BaseModel):
    """One declarative step: which registered action to run, and with what params.

    ``step_id`` is a stable, human-chosen label (e.g. ``"transition-to-investigating"``)
    unique within its own ``Playbook`` -- used to correlate this step's
    audit rows back to the exact step that produced them, since a playbook
    can legitimately reference the same ``action_name`` more than once with
    different params.
    """

    model_config = {"frozen": True}

    step_id: str = Field(min_length=1)
    action_name: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)


class Playbook(BaseModel):
    """A named, ordered, immutable sequence of steps -- pure data, never code."""

    model_config = {"frozen": True}

    playbook_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: str = Field(min_length=1)
    steps: tuple[PlaybookStep, ...] = Field(default_factory=tuple)


class PlaybookStepOutcome(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"


class PlaybookStepResult(BaseModel):
    """The real, complete record of one step's execution -- input, output,
    and decision, all in one place (roadmap H1's own "every step, input,
    output and decision recorded" requirement)."""

    model_config = {"frozen": True}

    step_id: str
    action_name: str
    params: dict[str, Any]
    outcome: PlaybookStepOutcome
    output: dict[str, Any] | None = None
    error: str | None = None


class PlaybookExecutionResult(BaseModel):
    """The full, replayable trace of one real ``Playbook`` execution.

    ``halted_early`` is ``True`` when a step failed and
    ``PlaybookExecutionService`` stopped before running the remaining steps
    (see that class's own docstring for the fail-fast reasoning) -- an
    honest record of "this run did not complete every declared step",
    never silently indistinguishable from a full run that simply had fewer
    steps.
    """

    model_config = {"frozen": True}

    execution_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    playbook_id: uuid.UUID
    playbook_name: str
    step_results: tuple[PlaybookStepResult, ...] = Field(default_factory=tuple)
    halted_early: bool = False
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def succeeded(self) -> bool:
        """True only if every declared step ran and every one succeeded."""
        return not self.halted_early and all(
            r.outcome == PlaybookStepOutcome.SUCCESS for r in self.step_results
        )
