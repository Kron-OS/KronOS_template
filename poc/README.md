# Verification-first PoCs

See `CLAUDE.md` Section F for the workflow these follow. Each PoC pair
below runs the **real** dependency at the version pinned in this repo,
using KronOS's own `src/` classes wherever possible instead of
reimplementations, and keeps its actual captured output alongside the code.

| Directory | Component pair | Status |
|---|---|---|
| `plaso/` | Plaso 20260512 alone, against a real forensic sample | 2 bugs found + fixed (binary names, psort pre-existing-file) |
| `opensearch/` | `src/adapter/opensearch/client.py` alone, against real OpenSearch 2.11.1 | 1 bug found + fixed (`opensearch-py[async]` extra); 1 gap documented (`ensure_tenant_role` untestable with security plugin disabled) |
| `plaso_opensearch/` | The two linked: real Plaso output through the real ingestion pipeline into real OpenSearch | 1 bug found + fixed (timestamp handling silently used ingest-time instead of forensic event-time) |

## Fixes this pass made to `src/`/`docker/` (not just `poc/`)

1. `docker/plaso/kronos-plaso-worker.py` — look up `log2timeline`/`psort`
   (unsuffixed) before falling back to the legacy `.py`-suffixed names.
2. `docker/plaso/kronos-plaso-worker.py` — stop pre-creating psort's output
   file (psort refuses to write to an existing file); still reserve a
   unique unpredictable name via `mkstemp`, just unlink it first.
3. `src/external/sandbox/firecracker.py` — `_stream_records()` now handles
   psort's int microsecond-epoch timestamps, not just ISO strings.
4. `pyproject.toml` — `opensearch-py[async]>=2.6` (was missing the extra
   that `AsyncOpenSearch` actually requires).

Before these fixes, Plaso parsing had never actually run in this repo — it
silently produced only placeholder events — despite parser code, worker
code, and tests referencing it as if it worked.

## Why existing tests didn't catch this

`tests/unit/parsers/test_real_world_samples.py` already runs three other
parsers (Nginx, CloudTrail, EVTX) against real-world sample bytes end-to-end
and found three real bugs that way (see that file's own docstring). For
Plaso it explicitly stops at `PlasoParser.supports()` (format detection)
and never calls `.parse()`, with a comment noting the subprocess path is
"excluded from unit coverage" — matching `pyproject.toml`'s
`coverage.run.omit` list (`src/external/parsers/plaso.py`,
`src/external/sandbox/firecracker.py`). That omission is *why* three
release-blocking bugs (wrong binary names, psort's pre-existing-file
rejection, and silently-wrong timestamps) went unnoticed: the one place
that tests real parsers against real bytes deliberately didn't do that for
the one parser that shells out to a real external tool. This PoC's
`run_poc.sh`/`run_poc.py` are not a replacement for an automated test, but
they're the shape a real integration test for `PlasoParser.parse()` should
take (real container, real sample, real assertions on output) — a
worthwhile follow-up outside this PoC pass's scope.
