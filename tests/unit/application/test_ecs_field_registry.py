"""Unit tests for the ECS field-mapping registry (roadmap M0/A2).

test_default_registry_fields_all_mapped_in_index_template is the CI check
the roadmap requires: it must fail if a registered ECS path isn't mapped in
the real index template, since that mismatch is exactly the silent-match
bug (docs/NEXTGEN_SOC_ROADMAP.md A1/A2) -- a Sigma rule referencing an
unmapped path matches nothing, with no error anywhere.
"""

from __future__ import annotations

from src.application.ecs_field_registry import (
    ECSFieldMappingRegistry,
    FieldMapping,
    get_default_registry,
    validate_against_index_template,
)

_INDEX_TEMPLATE_PATH = "src/adapter/opensearch/index_template.json"


class TestDefaultRegistry:
    def test_evtx_mapping_registered(self) -> None:
        registry = get_default_registry()
        mapping = registry.for_parser("evtx-rs")
        assert mapping is not None
        assert mapping["winlog.event_data.CommandLine"] == "process.command_line"
        assert mapping["winlog.event_data.Image"] == "process.executable"

    def test_unregistered_parser_returns_none(self) -> None:
        registry = get_default_registry()
        assert registry.for_parser("does-not-exist") is None

    def test_all_ecs_field_paths_nonempty(self) -> None:
        registry = get_default_registry()
        assert len(registry.all_ecs_field_paths()) > 0


class TestValidateAgainstIndexTemplate:
    def test_default_registry_fields_all_mapped_in_index_template(self) -> None:
        registry = get_default_registry()
        missing = validate_against_index_template(registry, _INDEX_TEMPLATE_PATH)
        assert missing == [], f"registry references ECS fields the index template doesn't map: {missing}"

    def test_detects_a_genuinely_unmapped_field(self) -> None:
        """Regression guard for the CI check itself: register a field that
        cannot possibly be in the real template and confirm the validator
        actually reports it, rather than silently passing everything."""

        class _BogusMapping(FieldMapping):
            @property
            def parser_name(self) -> str:
                return "bogus-test-parser"

            @property
            def mapping(self) -> dict[str, str]:
                return {"raw.bogus": "totally.unmapped.made.up.field"}

        registry = ECSFieldMappingRegistry()
        registry.register(_BogusMapping())
        missing = validate_against_index_template(registry, _INDEX_TEMPLATE_PATH)
        assert missing == ["totally.unmapped.made.up.field"]

    def test_registering_two_parsers_does_not_lose_either(self) -> None:
        registry = get_default_registry()
        registry.register(
            type(
                "_ExtraMapping",
                (FieldMapping,),
                {
                    "parser_name": property(lambda self: "extra-test-parser"),
                    "mapping": property(lambda self: {"raw.foo": "process.command_line"}),
                },
            )()
        )
        assert registry.for_parser("evtx-rs") is not None
        assert registry.for_parser("extra-test-parser") is not None
