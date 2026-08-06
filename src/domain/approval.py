"""ApprovalDecision domain model: the outcome of consulting an
``ApprovalGate`` before a destructive containment action is allowed to run
(roadmap M7/H2 -- the milestone's own binding gate: "prove no destructive
action can execute without either an explicit policy authorization or
human approval").

Pure, frozen data -- zero framework imports (CLAUDE.md SS A.3). The actual
policy/human-approval logic lives in ``ApprovalGate`` implementations
(``src/application/approval_gate.py``); this module only describes the
shape of their answer, mirroring how ``RiskFactor`` (``src/domain/risk.py``)
is the pure-data half of F4's scoring logic while the scoring itself lives
in the application layer.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ApprovalDecision(BaseModel):
    """Whether one specific containment-action attempt is authorized to proceed.

    ``policy_name`` identifies WHICH ``ApprovalGate`` implementation
    produced this decision (e.g. ``"step_up_mfa"``, ``"static_policy_allowlist"``)
    -- stored on the resulting ``CONTAINMENT_ACTION_DENIED``/``_EXECUTED``
    audit event so a containment action's audit trail records not just
    THAT it was gated, but by which mechanism, without needing to inspect
    application code to find out (mirrors ``Detection.rule_matches``' own
    "capture enough to be self-explanatory" principle).
    """

    model_config = {"frozen": True}

    authorized: bool
    policy_name: str = Field(min_length=1)
    reason: str = Field(min_length=1)
