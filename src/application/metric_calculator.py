"""MetricCalculator: the pluggable per-KPI computation unit (roadmap M8/I2).

Mirrors this codebase's established ABC+registry extensibility idiom
(``FieldMapping``/``ECSFieldMappingRegistry``, ``CostGateHeuristic``/
``RuleCostGate``, ``PlaybookAction``/``PlaybookActionRegistry``): a new KPI
is a new ``MetricCalculator`` subclass, added to ``MetricRegistry`` via one
``register()`` call -- zero edits to ``MetricRegistry``, ``MetricsService``,
or any other already-registered calculator.

Deliberately NOT wired into ``src/external/dependencies.py``/``startup.py``
in this pass -- mirrors G1's own ``RarityBaselineScorer`` precedent
(roadmap M6/G1: a standalone application-layer class, constructed directly
by whoever needs it -- a PoC script or a future route -- rather than forced
through the DI container before a real consumer of it exists). Wiring a
route is real, legitimate follow-up scope once a concrete UI/consumer is
decided, not fabricated here just to look "integrated".
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.domain.metrics import MetricResult
from src.domain.user import TenantContext


class MetricCalculator(ABC):
    """One independently-registered KPI computation."""

    @property
    @abstractmethod
    def metric_name(self) -> str:
        """Stable registry key (e.g. ``"sa_cycle_time_seconds"``)."""

    @abstractmethod
    async def compute(self, tenant: TenantContext) -> MetricResult:
        """Compute this metric scoped to *tenant*'s own org.

        *tenant* is always the authenticated caller's own ``TenantContext``
        (roadmap invariant #3) -- a calculator that genuinely needs to
        compute a cross-org/system metric must say so explicitly in its own
        docstring and must never use ``tenant.org_id`` to silently narrow
        (or fail to narrow) a query it claims is system-wide; every
        per-org calculator's own query MUST be scoped by ``tenant.org_id``,
        never by anything read out of the data it queries.

        Must never raise for "not enough real data exists yet to compute
        this meaningfully" -- that is an honest
        ``MetricResult(value=None, unavailable_reason=...)``, not an error
        (roadmap invariant #8: fail loudly, never fabricate). Only a
        genuine infrastructure failure (repository/OpenSearch/Redis
        unreachable) should raise.
        """


class MetricRegistry:
    """Holds registered ``MetricCalculator``s, keyed by their own ``metric_name``.

    A plain dict keyed by name, not a first-match-wins list: a caller
    always names the exact metric it wants (mirrors
    ``PlaybookActionRegistry``'s own reasoning, not ``ParserRegistry``'s
    content-sniffing one).
    """

    def __init__(self) -> None:
        self._calculators: dict[str, MetricCalculator] = {}

    def register(self, calculator: MetricCalculator) -> None:
        """Add *calculator*. A second registration under the same
        ``metric_name`` replaces the first -- callers that need to prevent
        that are responsible for checking ``get`` first; this registry only
        ever does bookkeeping, no policy (mirrors
        ``PlaybookActionRegistry.register``'s own contract)."""
        self._calculators[calculator.metric_name] = calculator

    def get(self, metric_name: str) -> MetricCalculator | None:
        return self._calculators.get(metric_name)

    def all_metric_names(self) -> tuple[str, ...]:
        return tuple(self._calculators.keys())


class MetricsService:
    """Computes one or all registered metrics for a tenant.

    Deliberately thin -- all real computation logic lives in each
    ``MetricCalculator``; this class only resolves names to calculators and
    fans out ``compute_all``, mirroring ``PlaybookExecutionService``'s own
    "orchestrator delegates, collaborators do the work" division of labor.
    """

    def __init__(self, registry: MetricRegistry) -> None:
        self._registry = registry

    async def compute(self, metric_name: str, tenant: TenantContext) -> MetricResult:
        calculator = self._registry.get(metric_name)
        if calculator is None:
            raise ValueError(f"Unknown metric: {metric_name!r}")
        return await calculator.compute(tenant)

    async def compute_all(self, tenant: TenantContext) -> list[MetricResult]:
        results = []
        for name in self._registry.all_metric_names():
            calculator = self._registry.get(name)
            assert calculator is not None  # noqa: S101 -- name came from this same registry
            results.append(await calculator.compute(tenant))
        return results
