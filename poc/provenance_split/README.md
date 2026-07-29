# provenance_split (B1 — L1)

**Component:** `src/domain/timeline.py` (`EvidenceProvenance`, formerly
`KronosProvenance`) + new `src/domain/stream.py` (`StreamProvenance`,
`Provenance` discriminated union). Pure domain-model change — no external
service. Pinned version: `pydantic>=2.7` in `pyproject.toml`; the venv this
repo actually runs (`/home/reca/venv`) has **pydantic 2.13.4** installed
(checked with `python3 -c "import pydantic; print(pydantic.VERSION)"`
before writing any union code, per CLAUDE.md §F.2 step 1). The discriminated
union syntax used below (`Annotated[Union[...], Field(discriminator=...)]`
+ `pydantic.TypeAdapter`) is the real, current pydantic v2 API — verified by
constructing and running it, not assumed from memory of an older version.

## Why a poc/ dir *and* full pytest tests, not just tests

CLAUDE.md §F's proof bar is about *real, executed* verification versus
plausible-but-unrun code — for a pure-Pydantic domain type with no I/O, the
pytest run **is** the real dependency run (the "real dependency" here is
pydantic's actual validation/serialization machinery, not a mock of it).
`tests/unit/domain/test_stream_provenance.py` already is that real,
captured, repeatable run. This `poc/` directory exists anyway, to match the
project's established `poc/<component>/` convention for an L1 item
(roadmap §2) and to give a single, minimal, from-scratch script that
demonstrates the three required behaviors without needing pytest's
machinery — useful as a quick, readable "does this actually work" artifact
independent of the test suite. Both are captured; neither is fabricated.

## What was demonstrated (see `output.txt` for the real run)

1. **Real construction** of both `EvidenceProvenance` (today's provenance,
   renamed from `KronosProvenance` — same fields, same validation, zero
   behavior change) and `StreamProvenance` (new; no `evidence_id`, no
   `sha256`, `case_id` optional).
2. **Real validation failures** per-type: `StreamProvenance` without
   `batch_id`/`source_id` raises `pydantic.ValidationError`;
   `EvidenceProvenance` without `evidence_id`/`sha256` raises the same —
   confirming the asymmetry is enforced, not just documented.
3. **Real discriminated-union round trip**: `TypeAdapter(Provenance)` given
   a `dict` with `kind="evidence"` produces an `EvidenceProvenance`
   instance; `kind="stream"` produces a `StreamProvenance` instance;
   `kind="carrier_pigeon"` (or missing) raises `ValidationError`; and
   `dump_python(mode="json") -> validate_python(...)` recovers the exact
   original object, proving the discriminator survives a real
   serialize/deserialize cycle (the shape a Redis Streams payload would
   take per roadmap D1).

## How to run

```
/home/reca/venv/bin/python3 poc/provenance_split/run_poc.py
```

Also exercised, more exhaustively, by:

```
/home/reca/venv/bin/pytest tests/unit/domain/test_stream_provenance.py tests/unit/domain/test_timeline.py -q --no-cov
```

## Design decision recorded here (see task report for full reasoning)

`TimelineRecord.kronos` is **not** widened to the `Provenance` union in this
pass — it stays `EvidenceProvenance` (functionally identical to
`KronosProvenance` today, only renamed). `KronosProvenance` is kept as a
plain alias (`KronosProvenance = EvidenceProvenance`) so all six existing
parsers, `firecracker.py`, `postgres_artifact.py`, and
`tests/fixtures/factories.py` keep working completely unmodified. Widening
`TimelineRecord.kronos` to the union, and updating those call sites, is
explicit follow-up scope (nothing in the pipeline produces a
`StreamProvenance` yet — that's roadmap D1/D2/D4).
