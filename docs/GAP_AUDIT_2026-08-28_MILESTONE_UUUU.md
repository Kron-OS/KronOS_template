# Gap Audit — Milestone UUUU (2026-09-01)

**Scope:** a real, reported bug — "indexes are not updated after parsing
and user can't update it manually, so we are not able to filter, for
example on event_identifier." Not a coverage/RBAC cycle; a real backend
fix to the OpenSearch indexing pipeline, found and verified live against
the real dev-stack OpenSearch 2.11.1 cluster per CLAUDE.md § F.

## The real issue, found by reading the actual mapping first

`src/adapter/opensearch/index_template.json` set `"dynamic": false` at
the mapping root, with exactly one narrow `dynamic_templates` rule
(`winlog.event_data.*` → keyword). Confirmed live against a real,
already-existing, already-populated dev-stack case index
(`kronos-kronos-dev-case-1a49dcd0-*-201508`, 388 real documents): any
field outside the curated `properties` allowlist and outside that one
subtree is accepted and stored in `_source`, but never added to the
Lucene index — silently unfilterable, no error anywhere.

This was a real, **already-acknowledged** trade-off, not a fresh
oversight: `poc/ecs_schema_hardening/` (a prior pass) fixed a worse bug
first — OpenSearch's default dynamic mapping maps a string field to
`text` + a `.keyword` sub-field, and a `term` query against the bare
field name (exactly what this platform's own Sigma-rule compilation and
`OpenSearchQueryBuilder.org_id_filter` both issue) silently matches
nothing against a `text` field. `dynamic: false` was the fix for THAT bug
— but that PoC's own README explicitly flagged today's exact complaint as
a known, deliberately-deferred follow-up: *"Existing indices: an index
template only applies to newly-created indices — live kronos-* indices
keep their current mapping... no reindex was performed as part of this
pass (out of scope)."*

### Why this bites much harder in practice than "wait for the next index"

`timeline_normalization.build_index_name` keys each per-case monthly
index name to the record's own **event timestamp**, not wall-clock time.
For a forensics platform whose whole point is analyzing *historical*
evidence, a case's index for (say) August 2015 is created exactly once —
the first time any 2015-08-dated record is ever parsed for that case —
and reused for every future parse of same-era evidence. It essentially
never naturally rotates to pick up a template-only fix, confirmed live
against the real 388-document index cited above (still on the pre-fix
mapping, unconditionally, before this change).

## The fix, in OpenSearch terms

1. **`src/adapter/opensearch/index_template.json`**: `"dynamic": true`
   at the root (was `false`), plus one general **`strings_as_keyword`**
   dynamic_template (`match_mapping_type: "string"` → `{"type":
   "keyword", "ignore_above": 1024}`, no `path_match` restriction — the
   real "auto-index any field" the report asked for). Does **not**
   reintroduce the original bug: unmapped strings become pure `keyword`
   directly, not OpenSearch's default `text`+`.keyword` split, so a
   bare-name `term` query still works. Explicit `properties` entries
   still take precedence over the catch-all for the curated ECS taxonomy
   — this is additive, not a replacement. Simplified two now-redundant
   `"dynamic": true` overrides (`winlog`, `winlog.event_data`) since the
   root setting now covers them.
2. **`src/adapter/opensearch/client.py`**:
   `OpenSearchClient.ensure_index_template()` — already called
   automatically on every single Celery ingest task (confirmed by reading
   `timeline_ingest.py` before touching anything, both call sites) — now
   *also* pushes the template's `dynamic`/`dynamic_templates` settings
   directly onto every already-existing `kronos-*` index via a live
   `_mapping` PUT. A real, supported, non-reindexing OpenSearch operation
   (you can change an index's dynamic-mapping behavior in place; you
   cannot change an already-mapped field's type in place). This is the
   "user can't update it manually" fix: fully automatic now, every
   ingest, zero admin action required. Tolerates a fresh cluster with
   zero `kronos-*` indices yet (`_mapping` on a wildcard matching nothing
   404s — confirmed live, a real no-op, not a failure — caught via
   `opensearchpy.exceptions.NotFoundError`).
3. **`scripts/reindex_kronos_dynamic_fields.py`** (new): the retroactive
   fix for documents already written before this change. Their dropped
   fields are still intact in `_source` (nothing was ever silently lost
   — `dynamic: false`'s own deliberate design), so `_update_by_query`
   re-processing each document against the index's now-current mapping
   recovers them — no re-parse of the original evidence needed.
   Deliberately **not** run automatically on every ingest (a real,
   potentially large/slow operation against already-live data, same
   reasoning `ecs_schema_hardening` already established for not
   reindexing unattended) — `--dry-run` lists affected indices first,
   real run is explicit and operator-triggered.

## Real, live verification (not assumed from reading the fix alone)

- `poc/opensearch_auto_index_fields/run_poc.py` against the real
  dev-stack OpenSearch 2.11.1: **19/19 passed** — the bug reproduced
  (unmapped field accepted, absent from the mapping, zero `term`-query
  hits, value still in `_source`); the live `_mapping` push onto an
  *already-existing* index confirmed (no reindex); a new document's new
  field auto-indexed and immediately term-queryable; the retroactive
  `_update_by_query` fix confirmed on the document written *before* the
  mapping fix; a genuinely fresh index behaves the same with zero extra
  steps; and the *original* Sigma-term-query bug confirmed **not**
  reintroduced (`kronos.org_id` still a real, bare-name-queryable
  `keyword`).
- `poc/opensearch_auto_index_fields/verify_real_client_code.py`: **3/3
  passed** (originally 4/4 — see the script's own note on its first,
  informational-only check) — calls the actual
  `OpenSearchClient.ensure_index_template()` Python method, not
  equivalent raw HTTP, against the real, already-populated
  `kronos-kronos-dev-case-1a49dcd0-*-201508` index (388 real documents,
  untouched otherwise); confirms it flips that live index to `dynamic:
  true`, confirms the catch-all template is present, confirms a real,
  freshly-written field in that same index is immediately
  term-queryable. The one verification document this script adds is
  deleted at the end.
- `scripts/reindex_kronos_dynamic_fields.py --dry-run` and a real
  (non-dry-run) run against a disposable scratch index both confirmed
  live — dry-run lists real matching indices with zero side effects; the
  real run correctly recovered a scratch document's searchability (0
  hits → 1 hit).
- New unit tests, `tests/unit/adapter/test_opensearch_client.py`: the
  live-mapping-sync call itself, tolerance of a fresh cluster (no
  matching indices), and re-raising any *other* real error rather than
  swallowing it.
- `tests/unit/application/test_ecs_field_registry.py`: 6/6 unchanged —
  the A2 registry's own "genuinely unmapped field" regression guard still
  correctly distinguishes an explicitly-curated field from one relying on
  the new dynamic fallback, confirming the two mechanisms don't collide.
- `~/venv/bin/python3 -m ruff check` / `mypy` on both changed files:
  clean.
- Full backend suite: `2063 passed, 2 skipped in 31.46s`, coverage
  90.44% (up from 2060/90.40% before this cycle — 3 new tests).

## Status

The reported bug is fixed at its real root cause, not worked around: new
fields (of any name, from any current or future parser) now auto-index
as real, filterable `keyword` fields, automatically, on every ingest,
with no manual step — and the fix reaches indices that already exist
today, not just ones created after this ships. A documented, explicit,
operator-run tool closes the retroactive gap for documents already
written before this fix, without needing to touch a single evidence
file or re-run any parser.

## Recommendation for the next cycle

1. Consider running `scripts/reindex_kronos_dynamic_fields.py` (for
   real, not `--dry-run`) against the real dev-stack's existing indices
   if retroactively recovering already-parsed evidence's dropped fields
   is wanted — deliberately not done as part of this cycle (an explicit,
   operator decision, not something to force unattended).
2. The OpenSearch Dashboards embed (Discover/Timeline tab) derives its
   own field list from the same live index mapping this fix updates — a
   good candidate for a quick manual spot-check (or a future
   `dashboards-embed.spec.ts` extension) confirming a newly-auto-indexed
   field actually appears as a real, filterable field in that UI too, not
   just via a raw OpenSearch query.
