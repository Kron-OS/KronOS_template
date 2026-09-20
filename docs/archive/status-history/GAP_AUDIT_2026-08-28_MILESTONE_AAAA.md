# Gap Audit — Milestone AAAA (2026-08-31)

**Naming note:** the first 4-letter milestone slug — `AAA` through `ZZZ`
was exhausted by Milestone ZZZ.

**Scope:** closes Milestone ZZZ's recommendation #1 — swap
`evidence-upload.spec.ts`'s synthetic CloudTrail fixture
(`tests/fixtures/samples/cloudtrail.json`) for the genuinely real,
already-committed `tests/fixtures/samples/real/aws_cloudtrail.jsonl`
sample. Flagged as a cheap, rigor-only follow-up, not a coverage gap —
it turned out to surface a real, previously-unknown, previously-latent
product bug the moment it was actually driven through the real pipeline.

---

## Found and fixed this cycle

### Real bug: `CloudTrailParser` could permanently fail real-world CloudTrail ingestion via a strict-type OpenSearch mapping conflict

Swapping the fixture and re-running the spec failed — not with a parsing
error, but with the *test's own 30s timeout*, because the evidence never
reached a terminal state. Investigated via real backend logs rather than
assumed to be a timing fluke: `celery-worker`'s own log showed

```
StorageError("OpenSearch bulk indexing had 1 document(s) fail out of 6
total. ... mapper_parsing_exception: failed to parse field [source.ip] of
type [ip] ... 'ec2.amazonaws.com' is not an IP string literal.")
```

Root-caused by directly reproducing the exact bulk-index call against the
real dev OpenSearch (not guessed): `CloudTrailParser` maps AWS's own
`sourceIPAddress` field straight to ECS's strictly `ip`-typed `source.ip`.
For most rows this is a real, valid IP — but the real fixture's own
`SharedSnapshotVolumeCreated` row has `sourceIPAddress: "ec2.amazonaws.com"`.
This is not malformed test data: AWS's own CloudTrail documentation states
that `sourceIPAddress` holds the *calling AWS service's hostname* (not a
client IP) for AWS-service-initiated events — a real, common, documented
shape in production CloudTrail logs, not an edge case. Celery retried
twice (30s apart, `max_retries` behavior for `parse_artefact_fast`), then
gave up — permanently sinking the evidence to `ERROR` in any real
deployment that ever ingested a CloudTrail log containing this common
event shape. This bug had been latent since `CloudTrailParser` shipped:
every existing unit test only ever exercised `parse()` in isolation, never
the real OpenSearch write path, so nothing had ever caught it.

**Fixed** per ECS's own convention for exactly this ambiguity: ECS defines
`source.address` for "some event source addresses... an IP, a domain, or
a unix socket... always store the raw address in the `.address` field."
`CloudTrailParser` now always populates `source.address` with the raw
value (added to `index_template.json`'s `source` object as `keyword`,
untyped-constrained) and only additionally populates the strictly
`ip`-typed `source.ip` when the value actually parses as a real IPv4/IPv6
address (new `_is_ip_literal()` helper, stdlib `ipaddress`).

**Verified at every step, not assumed**:
1. Directly reproduced the real bulk-index failure against the live dev
   OpenSearch with a standalone script (parser → ECS normalizer → real
   `AsyncOpenSearch.bulk()` call), capturing the exact `mapper_parsing_exception`
   before writing any fix.
2. Confirmed a `null` value for an `ip`-typed field does NOT itself error
   in OpenSearch (a real, targeted test against the live cluster) before
   relying on that as part of the fix design.
3. Re-ran the same direct reproduction after the fix: `0 errors out of 6`
   documents, with the service-linked row's real `source.address` value
   visible in the indexed document.
4. Restarted `celery-worker` (picks up both the code fix and re-applies
   the updated index template — confirmed via `ensure_index_template()`'s
   own idempotent-PUT-on-first-use behavior) and re-ran the real E2E spec:
   passes in ~7s (vs. timing out at 30s before the fix).
5. Ran the broader FAST-tier regression (`evidence-upload.spec.ts` +
   `evidence-upload-fast-parsers.spec.ts` + `login.spec.ts`, 6 tests) —
   all pass, confirming the index template change doesn't affect any other
   parser's own field mappings.
6. Added a real regression test,
   `test_service_linked_row_gets_source_address_not_a_bad_source_ip`
   (`tests/unit/parsers/test_real_world_samples.py`), asserting on the
   fixture's actual `SharedSnapshotVolumeCreated` row (not a synthetic
   case) that `source.address` is populated and `source.ip` is `None`,
   plus a normal-IP row still gets both fields populated correctly.

`ruff`/`mypy` clean on the changed Python file; `index_template.json`
JSON-validated.

## Status

A real, latent, previously-unknown bug that would have permanently broken
ingestion of a common, real-world CloudTrail event shape in any actual
deployment is fixed, tested, and verified live — found purely as a side
effect of the "cheap, rigor not coverage" fixture swap Milestone ZZZ
flagged, exactly the kind of catch this initiative's verification-first
discipline exists for (a synthetic fixture, no matter how well-intentioned,
cannot exercise a real-world data shape nobody thought to hand-write).

## Recommendation for the next cycle

1. Intake-stage retry E2E coverage (carried since Milestone TTT).
2. `security-stack` also booting `kronos-backend`, RBAC access-denial
   specs, `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8.
3. Given every parser now has real E2E coverage AND this cycle's fixture
   swap surfaced a real bug purely from using genuinely real data, it's
   worth a lower-effort audit of whether any OTHER already-covered
   parser's spec is still using a synthetic (not real) fixture that could
   be hiding a similar latent bug.
4. This initiative's own ~4-cycle assessment rhythm means the next
   multi-scenario subagent assessment is close to due (three
   implementation cycles — YYY, ZZZ, AAAA — have now landed since
   Milestone XXX).
