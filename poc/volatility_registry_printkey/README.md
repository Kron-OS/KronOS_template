# PoC: real, scoped windows.registry.printkey drill-down

**Version pinned**: `volatility3==2.28.0` (`docker/Dockerfile.plaso-worker`).
Run for real inside the live `docker-celery-worker-plaso-1` container against
the real 1.6 GB user-uploaded `Challenge.raw` Windows 7 image (real
investigative data on this org's live MinIO, not redistributed).

## What this verifies (Milestone EEEEE, plan Stage 3.6 item 4)

1. That a scoped, non-recursive `windows.registry.printkey` call (hive
   `offset` + optional `key` path, `recurse=False`) is fast and bounded --
   in contrast with the >200s unscoped recursive dump measured during this
   plan's own architecture research
   (`docs/GAP_AUDIT_2026-08-28_MILESTONE_CCCCC.md`).
2. The real, correct process shape for the on-demand "drill into a subkey"
   registry-browser UX the plan calls for.

## Real, captured results (`output.txt`)

- **`windows.registry.hivelist`**: 0.322s, 12 real hives with real paths
  (`\REGISTRY\MACHINE\SYSTEM`, `\SystemRoot\System32\Config\SOFTWARE`,
  `\??\C:\Users\Jaffa\ntuser.dat`, `\??\C:\Users\Jaffa\AppData\Local\...\UsrClass.dat`,
  etc.) -- genuine per-user and per-system hives from this real image.
- **`printkey`, hive root** (`offset=0xf8a000024010`, no `key`,
  `recurse=False`): **0.353s, 9 real rows** -- real SYSTEM hive top-level
  subkeys (`ControlSet001`, `ControlSet002`, `MountedDevices`, `RNG`,
  `Select`, `Setup`, `Software`, `WPA`, `CurrentControlSet`) with real
  `Last Write Time` timestamps.
- **`printkey`, drilled one level** (`offset=0xf8a000024010`,
  `key="ControlSet001"`, `recurse=False`): **0.344s, 5 real rows** -- real
  subkeys (`Control`, `Enum`, `Hardware Profiles`, `Policies`, `services`)
  with real timestamps.

Both scoped calls are **~0.35s**, three orders of magnitude faster than the
>200s unscoped recursive dump measured earlier -- confirms the scoped,
one-level-at-a-time drill-down design is the right UX shape, not just a
theoretical improvement.

## Real bug found and resolved: shared-Context reuse across repeated printkey calls

The first version of this script reused ONE shared `volatility3.Context`
across all three calls (mirroring `poc/volatility_multiplugin/`'s
proven pattern for *different* plugin types sharing one context). The
first two calls (`hivelist`, root `printkey`) succeeded. The second
`printkey` call -- drilling into `ControlSet001`, targeting the SAME hive
as the first `printkey` call, on the SAME shared context -- failed with:

```
volatility3.framework.exceptions.LayerException: Layer already exists: hive0xf8a000024010
```

Root cause: `printkey` internally calls `HiveList.list_hives()`, which does
`context.layers.add_layer(hive)`. The first `printkey` call already
registered a layer named `hive0xf8a000024010` into the shared context and
volatility3 never deregisters it between calls -- a second call targeting
the same hive collides on `add_layer()`.

**Resolution**: give each `printkey` invocation its own fresh `Context()`
(see `run_plugin()` in `run_poc.py`) rather than sharing one context across
repeated calls to the same plugin type. This is not a workaround bolted onto
the PoC -- it is the exact shape the real production design already
requires: each on-demand registry-drilldown click enqueues its own new
Celery task, which spawns its own new worker subprocess with its own new
`Context` from scratch. The shared-context optimization from
`poc/volatility_multiplugin/` only applies to the EAGER pipeline (one
worker invocation running several *different* plugin types together);
it does not apply to, and does not need to apply to, repeated on-demand
calls to the *same* plugin.

## Status

**PASS.** Real, scoped, non-recursive `printkey` calls are fast (~0.35s)
and bounded, and the fresh-Context-per-call shape (naturally matching the
real Celery-task-per-click design) resolves the only real issue
encountered. Design confirmed: on-demand registry-browser endpoint takes
`hive_offset` + optional `key`, `recurse=False` always, one new worker
subprocess invocation per request -- no long-lived shared context needed or
wanted for this path.

## Re-verification against the real, shipped worker script (Milestone EEEEE)

`docker/volatility/kronos-volatility-worker.py` was extended with a real
`--registry-hive-offset OFFSET [--registry-key KEY]` mode
(`_run_registry_printkey()`, always a fresh `Context`, matching this PoC's
own resolution). Run for real inside `docker-celery-worker-plaso-1`
against the same real `Challenge.raw`, hive offset `0xf8a000024010`:

- Root call: `status=ok`, 9 rows, identical real subkey names/timestamps to
  this PoC's own captured output.
- Drill call (`--registry-key ControlSet001`): `status=ok`, 5 rows,
  identical real subkey names/timestamps to this PoC's own captured output.

The worker mode is now the real implementation `VolatilityLauncher` calls,
not just this scratch PoC script.
