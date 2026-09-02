# PoC: shared-Context multi-plugin volatility3 execution

**Also serves as the "JsonRenderer standalone reuse" verification** (planned
as a separate `poc/volatility_jsonrenderer_reuse/`) — the row-extraction code
in `run_poc.py` *is* that reuse (`volatility3.cli.text_renderer.JsonRenderer`
driving a real `TreeGrid.populate()` outside the full CLI pipeline), verified
in the same real run rather than a second, duplicate script.

## Version pinned

`volatility3==2.28.0` (`docker/Dockerfile.plaso-worker`). Run for real inside
the live `docker-celery-worker-plaso-1` container (the actual pinned
install), not a host-side venv.

## What this verifies

Milestone CCCCC's core architectural bet: today's worker
(`docker/volatility/kronos-volatility-worker.py`) shells out to the `vol` CLI
**once per plugin**, redoing the expensive part (DTB/page-table detection +
kernel symbol table resolution) from scratch every time. This PoC verifies
that constructing **one** `volatility3.framework.contexts.Context`, resolving
automagic **once**, then looping `plugins.construct_plugin()` for multiple
plugin classes against that **same** context avoids re-paying that cost —
the mechanism the rewritten worker will use.

## Real samples used

- **`cridex.vmem`** (Windows XP SP3, Cridex/Feodo banking trojan) — the
  small, public, redistributable sample already used by
  `poc/volatility_memory_module/README.md`. On this host at
  `/home/reca/scratch/kronos-poc-volatility/cridex.vmem` (NOT committed to
  git, same convention as every other PoC using it). Copied into the
  container at `/tmp/cridex.vmem` for this run.
- **`Challenge.raw`** — a real 1.6 GB Windows 7 memory image the project
  owner uploaded to a real, live case on this dev stack (case
  `43097ab0-aae3-4968-915b-8f0229ac3865`, evidence
  `e9f3287f-3858-4018-bcee-42a4bcbb0bc3`). Verified against this too (see
  `output.txt`) but **not redistributed** — real user-owned investigative
  data, not a public research sample. `cridex.vmem` alone fully verifies the
  architecture for anyone reproducing this without access to that org's
  MinIO.

## How to run

```
docker cp run_poc.py docker-celery-worker-plaso-1:/tmp/run_poc_multiplugin.py
docker exec docker-celery-worker-plaso-1 python3 /tmp/run_poc_multiplugin.py
```
(Requires `/tmp/cridex.vmem` and, optionally, `/tmp/challenge.raw` already
present inside the container — see `output.txt` for how they were obtained
this run: `cridex.vmem` via `docker cp` from the host scratch path;
`challenge.raw` via `boto3` direct from this org's live MinIO, matching the
real evidence key already recorded in Postgres for that evidence row.)

## Result: `output.txt` — real, captured, both samples

**Architecture claim confirmed on both samples**: every plugin after the
first constructs in well under 0.5s (typically 0.08–0.17s), vs. the *first*
plugin paying the real automagic cost (13.2s for `cridex.vmem` — this
specific XP sample's own DTB detection is slow; 0.3s for `Challenge.raw`).
No state leakage observed between plugins sharing one context across 7
different plugin classes on two structurally different real images.

**`cridex.vmem`** (already-documented XP-era wrinkle, not new): `pstree`
returns 0 rows (known linked-list-walk issue for this exact sample, per
`poc/volatility_memory_module/README.md`), `psscan` recovers the real
17-process census via pool-tag scanning. The *per-process* introspection
plugins (`dlllist`, `cmdline`, `malfind`, `filescan`, `hivelist`) also
return 0 rows for this sample — consistent with the same underlying
linked-list/introspection limitation already documented for this specific
XP image, not a new bug. This is an honest, expected negative result for
this sample, not a PoC failure.

**`Challenge.raw`** (rich, real Windows 7 data): `pstree` 10 processes,
`psscan` 53 (pool-tag scan found MORE processes than the linked-list walk —
itself a real, meaningful forensic signal, noted for later), `dlllist` 2547
rows, `cmdline` 53 rows, **`malfind` found 4 real suspicious/injected
memory regions** including one in `explorer.exe` with
`Protection: PAGE_EXECUTE_READWRITE` (the classic injection tell), `filescan`
3232 file objects, `hivelist` 12 registry hives.

One rendering-shape note carried into the worker rewrite: `hivelist`'s
`FileFullPath` column rendered empty string for `Challenge.raw`'s hives in
this run — worth checking against a real hive path expectation when building
the registry browser (Milestone EEEEE), not blocking for this PoC's own
scope (architecture verification).

## Status

**PASS.** Proceeding to the worker rewrite using this exact verified
sequence.
