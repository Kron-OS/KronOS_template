# PoC: YARA scanning in the recursion path → StructuredArtifact (roadmap M4/E3)

## Versions (pinned, matching this session's other YARA/container PoCs)

- Postgres: `docker-postgres-1` (`postgres:16-alpine`).
- `yara-x`: `1.19.0` (`pyproject.toml` pin), via the real, unmodified
  `YaraXSandboxRunner` (roadmap E2) — real subprocess worker
  (`docker/yara/kronos-yarax-worker.py`), no in-process rule compilation.

## Why this isn't driven through the full HTTP evidence-intake API

No real YARA ruleset exists in production yet — E4 (ruleset
signing/lifecycle) hasn't started. `configure_dependencies()` is
deliberately never given a fake default `yara_runner`/`yara_rule_provider`
(the "honestly disabled" idiom this codebase already uses for
`RFC3161TimestampService` etc.). This PoC instead constructs the real
`ZipArchiveParser`/`TarArchiveParser` + real `YaraXSandboxRunner` + real
`DirectoryYaraRuleProvider` directly and persists through the real
`PostgresArtifactRepository` — the same level `ArtifactIngestService`
itself already operates at.

## What this actually does

**Scenario (a)** — a real zip containing a benign member, a member with a
byte pattern a real YARA-X rule matches, and a member that is itself a
nested tar (containing its own matching member). Confirms:
- Exactly 3 real matches: the direct member, the nested tar's own raw
  bytes (tar has no compression — the outer container-as-a-blob genuinely
  does contain the inner member's bytes verbatim, so scanning the raw
  member *and* recursing into it are both correct, not double-counting),
  and the correctly-recursed inner member with its `source_path` properly
  prefixed (`nested.tar/nested_evil.bin`).
- Real Postgres rows (independent raw SQL query, not the repository's own
  round trip) with correct `container_sha256` (the top-level evidence's
  real sha256) and `org_id` (from the tenant, never the payload).
- Real, correct byte offsets or matched strings.

**Scenario (b)** — a malformed ruleset produces a clean compile-error
abort: zero artifacts, no exception, and `parse()`'s own `TimelineRecord`
output for the very same evidence is completely unaffected.

**Scenario (c)** — independently measures the real, complete
`YaraXSandboxRunner.run()` round trip (not just a bare subprocess launch)
to sanity-check `ZipArchiveParser.extract_artifacts()`'s own docstring
claim about per-member cost.

## Real bug found and fixed — in this PoC script, not `src/`

The first run produced only 2 matches, not 3, and then crashed
(`StopIteration`) looking for the recursed inner member's row. Root cause:
the script had registered a `TarArchiveParser` **without** the yara
collaborators into the `ParserRegistry`, then called `extract_artifacts()`
on a *separately constructed*, correctly-configured `ZipArchiveParser` that
was never itself registered. When that instance recursed into the nested
tar member, `_recurse_into_nested_container` resolves the nested parser via
`self._registry.get_parser(...)` — i.e. the **registry's own** registered
instance, not whatever instance `extract_artifacts()` happened to be called
on. The registry's `TarArchiveParser` had no runner/provider configured, so
recursive scanning silently did nothing.

This is exactly the real `src/external/dependencies.py::get_parser_registry()`
wiring pattern already gets right (both `ZipArchiveParser` and
`TarArchiveParser` are constructed with the *same* `_yara_runner`/
`_yara_rule_provider` module-level values) — the PoC script itself had
diverged from that pattern. Fixed by registering both parsers with the
same real collaborators, matching production wiring exactly. 12/12 checks
passed once corrected.

## Real finding: the E3 implementation's own docstring cost estimate was optimistic

Scenario (c) measured a bare `python3 -c 'pass'` subprocess launch at
~12.8ms (matching the original docstring's ~13ms claim), but the *complete*
`YaraXSandboxRunner.run()` round trip — the real worker script, which
additionally imports `yara_x` (a real Rust extension with its own load
cost) and does real rule-file/target-file I/O — measured **~58ms per
member**, not the ~16ms (~13ms launch + ~2.7ms compile + ~0.03ms scan) an
earlier, narrower in-process-only measurement implied.
`ZipArchiveParser.extract_artifacts()`'s docstring has been corrected to
state the real, complete number. The conclusion is unchanged (even a
pathological 500-member container adds only ~29s, still well inside a
HEAVY Celery task's multi-minute budget), but the number backing it is now
honest, not optimistic.

## Result: `output.txt` — 12/12 real checks passed (after the PoC-script fix above)

## Explicitly flagged, not yet done

Same as the roadmap's own E3 STATUS note:
- Plaso-internal per-file scanning (files Plaso extracts from inside a
  disk image during its own dfVFS-based parsing) is out of scope and
  confirmed real — Plaso doesn't expose raw per-file bytes, only
  `TimelineRecord`-shaped events about files.
- Nothing wires a real ruleset into production DI yet (E4 doesn't exist).
- `YaraXSandboxRunner.run()` recompiles the combined rule source per
  member, not per rule — fine at the real measured cost above.
