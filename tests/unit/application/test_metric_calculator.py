"""Unit tests for MetricCalculator/MetricRegistry/MetricsService (roadmap M8/I2)."""

from __future__ import annotations

import pytest

from src.application.metric_calculator import MetricCalculator, MetricRegistry, MetricsService
from src.domain.metrics import MetricResult
from src.domain.user import TenantContext
from tests.fixtures.factories import make_tenant_context


class _StubCalculator(MetricCalculator):
    def __init__(self, name: str, value: float | None = 1.0) -> None:
        self._name = name
        self._value = value
        self.compute_calls: list[TenantContext] = []

    @property
    def metric_name(self) -> str:
        return self._name

    async def compute(self, tenant: TenantContext) -> MetricResult:
        self.compute_calls.append(tenant)
        return MetricResult(
            metric_name=self._name,
            org_id=tenant.org_id,
            value=self._value,
            unit="count",
            sample_size=1,
        )


class TestMetricRegistry:
    def test_register_then_get(self) -> None:
        registry = MetricRegistry()
        calc = _StubCalculator("foo")

        registry.register(calc)

        assert registry.get("foo") is calc

    def test_get_unknown_returns_none(self) -> None:
        registry = MetricRegistry()
        assert registry.get("does_not_exist") is None

    def test_second_registration_under_same_name_replaces_first(self) -> None:
        registry = MetricRegistry()
        first = _StubCalculator("foo", value=1.0)
        second = _StubCalculator("foo", value=2.0)

        registry.register(first)
        registry.register(second)

        assert registry.get("foo") is second

    def test_all_metric_names_reflects_registrations(self) -> None:
        registry = MetricRegistry()
        registry.register(_StubCalculator("foo"))
        registry.register(_StubCalculator("bar"))

        assert set(registry.all_metric_names()) == {"foo", "bar"}


class TestMetricsService:
    @pytest.mark.asyncio
    async def test_compute_delegates_to_registered_calculator(self) -> None:
        registry = MetricRegistry()
        calc = _StubCalculator("foo", value=42.0)
        registry.register(calc)
        service = MetricsService(registry)
        tenant = make_tenant_context()

        result = await service.compute("foo", tenant)

        assert result.value == 42.0
        assert result.org_id == tenant.org_id
        assert calc.compute_calls == [tenant]

    @pytest.mark.asyncio
    async def test_compute_unknown_metric_raises(self) -> None:
        service = MetricsService(MetricRegistry())

        with pytest.raises(ValueError, match="Unknown metric"):
            await service.compute("nope", make_tenant_context())

    @pytest.mark.asyncio
    async def test_compute_all_returns_every_registered_metric(self) -> None:
        registry = MetricRegistry()
        registry.register(_StubCalculator("foo", value=1.0))
        registry.register(_StubCalculator("bar", value=2.0))
        service = MetricsService(registry)

        results = await service.compute_all(make_tenant_context())

        assert {r.metric_name for r in results} == {"foo", "bar"}
        assert {r.value for r in results} == {1.0, 2.0}

    @pytest.mark.asyncio
    async def test_compute_all_empty_registry_returns_empty_list(self) -> None:
        service = MetricsService(MetricRegistry())
        assert await service.compute_all(make_tenant_context()) == []


class TestMetricResult:
    def test_is_available_true_when_value_present(self) -> None:
        result = MetricResult(metric_name="x", org_id=None, value=0.0, unit="ratio", sample_size=1)
        assert result.is_available is True

    def test_is_available_false_when_value_none(self) -> None:
        result = MetricResult(
            metric_name="x",
            org_id=None,
            value=None,
            unit="ratio",
            sample_size=0,
            unavailable_reason="no data",
        )
        assert result.is_available is False
