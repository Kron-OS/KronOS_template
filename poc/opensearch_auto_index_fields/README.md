# Milestone UUUU: auto-index every parser field

**Real user report:** after parsing, a genuinely new/uncommon field (the
report's own example: `event_identifier`) could not be filtered on, and
there was no way to fix it manually.

## The real issue, found by reading the actual mapping first

`src/adapter/opensearch/index_template.json` set `"dynamic": false` at the
root, with exactly ONE narrow `dynamic_templates` rule
(`winlog.event_data.*` → keyword). Confirmed live against a real,
already-existing dev-stack case index (`docker exec ... _mapping`): any
field outside the explicit `properties` allowlist and outside that one
subtree — a different parser's own `extra[]` output, or any genuinely new
field — is accepted and stored in `_source`, but **never added to the
Lucene index**. Silently unfilterable, no error anywhere.

This was a real, previously-**acknowledged** trade-off, not an oversight:
`poc/ecs_schema_hardening/` fixed a worse bug first (`dynamic: true`'s
OpenSearch default maps strings to `text` + a `.keyword` sub-field, and a
`term` query against the bare field name — exactly what this platform's
own Sigma-rule compilation and `OpenSearchQueryBuilder.org_id_filter`
both do — silently matches nothing). That PoC's own README explicitly
flagged today's exact complaint as a known follow-up: *"Existing indices:
an index template only applies to newly-created indices — live kronos-*
indices keep their current mapping... no reindex was performed as part of
this pass (out of scope)."*

**Why this bites much harder in practice than "wait for the next
index"**: `timeline_normalization.build_index_name` keys the per-case
monthly index name to each record's own **event timestamp**, not
wall-clock time. For a forensics platform whose whole point is analyzing
*historical* evidence, a case's index for (say) August 2015 is created
once, the first time any 2015-08-dated record is ever parsed for that
case, and is then reused for every future parse of same-era evidence —
it essentially never naturally rotates to pick up a template fix.
Confirmed live: `kronos-kronos-dev-case-1a49dcd0-*-201508` (a real,
already-populated case index, 388 real documents) was still on the
pre-fix mapping before this change, unconditionally.

## The fix, in OpenSearch terms

1. **`dynamic: true`** at the template root (was `false`), plus a single
   general **`strings_as_keyword`** dynamic_template
   (`match_mapping_type: "string"` → `{"type": "keyword", "ignore_above":
   1024}`, no `path_match` restriction — applies everywhere). This is the
   real "auto-index any field" the report asked for, and it does **not**
   reintroduce the original bug: unmapped strings become pure `keyword`
   fields directly, not OpenSearch's own default `text`+`.keyword`
   multi-field split, so a bare-name `term` query still works. Explicit
   `properties` entries still take precedence over the catch-all for
   everything this platform's own queries are known to depend on — this
   is additive, not a replacement for the curated ECS taxonomy.
2. **`OpenSearchClient.ensure_index_template()`** (already called
   automatically on every single Celery ingest task, confirmed by reading
   `timeline_ingest.py` before touching anything) now ALSO pushes the
   template's `dynamic`/`dynamic_templates` settings directly onto every
   already-existing `kronos-*` index via a live `_mapping` PUT — a real,
   supported, non-reindexing OpenSearch operation (you can change an
   index's dynamic-mapping behavior in place; you cannot change an
   already-mapped field's type in place). This is the "user can't update
   it manually" fix: it is now fully automatic, every ingest, zero admin
   action required. Tolerates a fresh cluster with zero `kronos-*`
   indices yet (`_mapping` on a wildcard matching nothing 404s — a real
   no-op, confirmed live, not a failure).
3. **Retroactive fix for documents already written** before this change:
   their dropped fields are still intact in `_source` (nothing was ever
   silently lost), so `_update_by_query` re-processing each document
   against the index's now-current mapping recovers them — verified live,
   no re-parse of the original evidence needed. Deliberately **not** run
   automatically on every ingest (a real, potentially large/slow
   operation against already-live data — same reasoning
   `ecs_schema_hardening` already established for not reindexing
   unattended). `scripts/reindex_kronos_dynamic_fields.py` is a real,
   documented, explicitly-run tool for this — `--dry-run` lists affected
   indices first.

## Verified, for real

`run_poc.py` against the real, live dev-stack OpenSearch 2.11.1: **19/19
passed** — the bug reproduced (unmapped field accepted, absent from the
mapping, zero `term`-query hits, value still in `_source`); the live
`_mapping` push onto an **already-existing** index confirmed (no
reindex); a new document's new field auto-indexed and immediately
term-queryable; the retroactive `_update_by_query` fix confirmed on the
document written *before* the mapping fix; a genuinely fresh index
behaves the same with zero extra steps; and the **original** bug
(`ecs_schema_hardening`'s own fix) confirmed NOT reintroduced — an
explicitly-mapped ECS field (`kronos.org_id`) is still a real,
bare-name-queryable `keyword`.

`verify_real_client_code.py` against the real, live dev-stack: **4/4
passed** — calls the actual `OpenSearchClient.ensure_index_template()`
Python method (not equivalent raw HTTP) against a real, already-existing,
already-populated case index (`kronos-kronos-dev-case-1a49dcd0-*-201508`,
388 real documents), confirms it flips that live index from `dynamic:
false` to `true`, confirms the catch-all template is now present, and
confirms a real, freshly-written field in that same index is immediately
term-queryable. The one verification document this script adds is
deleted at the end; no real case data is modified.

`scripts/reindex_kronos_dynamic_fields.py --dry-run` and a real
(non-dry-run) run against a disposable scratch index both confirmed live
— `--dry-run` correctly lists real matching indices with zero side
effects; the real run correctly re-processed a scratch document (0 hits
→ 1 hit after running).

`~/venv/bin/python3 -m pytest tests/unit/adapter/test_opensearch_client.py
tests/unit/application/test_ecs_field_registry.py`: 23/23 passed (3 new:
the live-mapping-sync call, the fresh-cluster no-op tolerance, and
re-raising any *other* real error). Full suite:
`2063 passed, 2 skipped`, 90.44% coverage (up from 2060/90.40% before
this change).

## Where this lives in the project

- `src/adapter/opensearch/index_template.json` — the actual mapping
  policy fix (`dynamic: true` + `strings_as_keyword`).
- `src/adapter/opensearch/client.py` — `OpenSearchClient.ensure_index_template()`,
  now also syncing live indices. Already wired into the real ingest path
  (`src/application/timeline_ingest.py`, `TimelineIngestionService.ingest_records()`)
  with zero new call sites needed.
- `scripts/reindex_kronos_dynamic_fields.py` — the explicit,
  operator-run retroactive fix for documents indexed before this change.
- `tests/unit/adapter/test_opensearch_client.py` — the regression guard.
