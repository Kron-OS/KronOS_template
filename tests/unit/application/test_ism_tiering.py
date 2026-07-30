"""Unit tests for DefaultIsmTierResolver (pure domain logic, no mocks needed)."""

from __future__ import annotations

from src.application.ism_tiering import DefaultIsmTierResolver


class TestPolicyIdForSource:
    def test_case_scoped_none_resolves_to_standard_tier(self) -> None:
        resolver = DefaultIsmTierResolver()
        assert resolver.policy_id_for_source(None) == "kronos-rollover"

    def test_known_high_volume_sources_resolve_to_aggressive_tier(self) -> None:
        resolver = DefaultIsmTierResolver()
        for source in ("network", "firewall", "flow", "dns"):
            assert resolver.policy_id_for_source(source) == "kronos-stream-aggressive"

    def test_unlisted_source_falls_back_to_standard_tier(self) -> None:
        resolver = DefaultIsmTierResolver()
        assert resolver.policy_id_for_source("some-future-source") == "kronos-rollover"


class TestPolicyBodyForId:
    def test_standard_policy_body_loads_the_real_ism_policy_json(self) -> None:
        resolver = DefaultIsmTierResolver()
        body = resolver.policy_body_for_id("kronos-rollover")
        assert body["policy"]["ism_template"][0]["index_patterns"] == ["kronos-*"]

    def test_aggressive_policy_body_loads_the_real_aggressive_json(self) -> None:
        resolver = DefaultIsmTierResolver()
        body = resolver.policy_body_for_id("kronos-stream-aggressive")
        assert body["policy"]["ism_template"][0]["priority"] == 200
