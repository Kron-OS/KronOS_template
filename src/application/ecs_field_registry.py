"""Registry mapping a parser's raw/native field names to canonical ECS field
paths, so Sigma-style detection rules can reference one stable vocabulary
instead of per-parser field names.

Not every parser needs an entry here: SuricataEveParser (verified by reading
src/external/parsers/suricata.py) already writes ECS-shaped dotted keys
directly into TimelineRecord.extra (e.g. "source.ip", "destination.port") --
nothing to translate. FastEvtxParser (verified by reading
src/external/parsers/evtx.py) preserves raw Windows EventData field names
under a "winlog.event_data.*" namespace (e.g. "winlog.event_data.CommandLine"),
which is where most public Sigma "windows" rules expect "process.command_line"
et al -- that mismatch is the real, concrete instance of the A1 silent-match
bug this registry exists to close.

Extensibility: a new parser needing translation registers its own
FieldMapping in get_default_registry(); no edits to existing FieldMapping
classes or to ECSFieldMappingRegistry itself are required.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping


class FieldMapping(ABC):
    """Maps one parser's raw/native field names to canonical ECS field paths."""

    @property
    @abstractmethod
    def parser_name(self) -> str:
        """Must match the owning ForensicParser's own parser_name property."""

    @property
    @abstractmethod
    def mapping(self) -> Mapping[str, str]:
        """raw extra-dict key -> canonical ECS dotted field path."""


class EvtxFieldMapping(FieldMapping):
    """FastEvtxParser stores raw Windows EventData under
    winlog.event_data.<RawName> (see evtx.py's own
    `extra[f"winlog.event_data.{k}"] = v`). Sigma's windows-category rules
    key on Sysmon/ECS-style names instead -- this is that translation.
    """

    @property
    def parser_name(self) -> str:
        return "evtx-rs"

    @property
    def mapping(self) -> Mapping[str, str]:
        return {
            "winlog.event_data.CommandLine": "process.command_line",
            "winlog.event_data.Image": "process.executable",
            "winlog.event_data.ParentImage": "process.parent.executable",
            "winlog.event_data.ParentCommandLine": "process.parent.command_line",
            "winlog.event_data.TargetFilename": "file.path",
            "winlog.event_data.DestinationIp": "destination.ip",
            "winlog.event_data.DestinationPort": "destination.port",
            "winlog.event_data.SourceIp": "source.ip",
            "winlog.event_data.QueryName": "dns.question.name",
            "winlog.event_data.TargetObject": "registry.path",
            "winlog.event_data.Details": "registry.value",
            # Deliberately NOT mapping "winlog.event_data.Hashes" here: Sysmon's
            # raw Hashes field is a composite string ("MD5=...,SHA256=..."),
            # not a bare hash value -- a plain rename to file.hash.sha256 would
            # misrepresent the data. Needs real parsing logic (split on the
            # algorithm prefix) before it can map safely; flagged as
            # follow-up, not guessed at here.
        }


class ECSFieldMappingRegistry:
    """Collects FieldMapping instances. DI-registered, not a hardcoded
    if/elif lookup -- see get_default_registry()."""

    def __init__(self) -> None:
        self._mappings: dict[str, FieldMapping] = {}

    def register(self, mapping: FieldMapping) -> None:
        self._mappings[mapping.parser_name] = mapping

    def for_parser(self, parser_name: str) -> Mapping[str, str] | None:
        found = self._mappings.get(parser_name)
        return found.mapping if found is not None else None

    def all_ecs_field_paths(self) -> set[str]:
        """Every canonical ECS path any registered mapping can produce --
        the set the index template must cover (see validate_against_index_template)."""
        paths: set[str] = set()
        for m in self._mappings.values():
            paths.update(m.mapping.values())
        return paths


def get_default_registry() -> ECSFieldMappingRegistry:
    registry = ECSFieldMappingRegistry()
    registry.register(EvtxFieldMapping())
    # NOTE: CloudTrailParser, NginxParser, PlasoParser, ChromeHistoryParser
    # have not yet been individually inspected for raw-vs-ECS field naming
    # the way evtx.py/suricata.py were here -- do not assume they're either
    # "fine" or "need translation" without reading their actual extra[]
    # writes first. Flagged as remaining A2 scope in
    # docs/NEXTGEN_SOC_ROADMAP.md.
    return registry


def validate_against_index_template(
    registry: ECSFieldMappingRegistry, index_template_path: str
) -> list[str]:
    """Returns ECS field paths the registry references that the index
    template does NOT map. Empty = OK. Call this from CI -- a non-empty
    result is exactly the silent-match bug from
    docs/NEXTGEN_SOC_ROADMAP.md A1/A2: a Sigma rule referencing one of these
    paths would match nothing, with no error anywhere.
    """
    with open(index_template_path, encoding="utf-8") as f:
        template = json.load(f)
    mapped_paths = _flatten_mapped_paths(template["template"]["mappings"]["properties"])
    return sorted(p for p in registry.all_ecs_field_paths() if p not in mapped_paths)


def _flatten_mapped_paths(properties: dict, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    for key, spec in properties.items():
        full = f"{prefix}{key}"
        if "properties" in spec:
            paths |= _flatten_mapped_paths(spec["properties"], prefix=f"{full}.")
        else:
            paths.add(full)
    return paths
