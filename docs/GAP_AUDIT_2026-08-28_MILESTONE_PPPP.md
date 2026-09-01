# Gap Audit — Milestone PPPP (2026-09-01)

**Scope:** not a feature/coverage milestone — two stale, previously-documented
tooling-gap claims corrected after actually re-checking them live, per
CLAUDE.md § F's own standard ("no integration is 'done' — or, here, 'not
possible' — without being run against the real thing and the output
inspected"). Both were flagged as candidate follow-ups in Milestone OOOO's
own recommendation list; re-verified rather than assumed still true.

## 1. Python 3.14 no longer deadlocks on this host

`docs/PRODUCT_STATUS_AND_V2_PREVIEW.md` and `PROGRESS.md` both stated this
host's Python 3.14 venv deadlocks inside native `asyncpg`/`greenlet` code
during test collection (a real, previously-observed `SIGABRT`). Re-ran the
full suite fresh before trusting that claim any further:

```
~/venv/bin/python3 -m pytest tests/
...
TOTAL   10357  995  90%
Required test coverage of 80% reached. Total coverage: 90.39%
2056 passed, 2 skipped, 19 warnings in 29.87s
```

No hang, no crash, real coverage gate pass. Ran incrementally first
(domain unit tests, routes unit tests, individual integration files, the
full `tests/unit/` tree, then `tests/integration/`, then everything
together) rather than assuming the full run would work from the first
narrow success — each step passed cleanly. Whatever native-wheel/dependency
mismatch caused the original deadlock was evidently resolved by a later
`pip install` or venv rebuild between sessions; not investigated further
since the practical blocker (an unusable local test run) is what mattered
and it's gone. **CI's own Python 3.11 pin is unrelated to this finding
and unchanged** — this is about *this host's* venv being usable now, not
a reason to relax CI's pinned version.

Corrected: `docs/PRODUCT_STATUS_AND_V2_PREVIEW.md`'s "Tooling/environment
gaps" section, `PROGRESS.md`'s "Test suite provenance" note and its Part
3.2 checklist item.

## 2. `helm` is installed on this host

Same pattern: `docs/PRODUCT_STATUS_AND_V2_PREVIEW.md` and `PROGRESS.md`
both stated the `helm` binary isn't installed on this host. It is —
`/usr/local/bin/helm`, `v3.16.4+g7877b45`. Re-ran both real checks:

```
$ helm lint charts/kronos
==> Linting charts/kronos
[INFO] Chart.yaml: icon is recommended
1 chart(s) linted, 0 chart(s) failed

$ helm template kronos charts/kronos
(exit 0, 3653 lines, 57 resources: ConfigMap×8, Deployment×6,
 HorizontalPodAutoscaler×1, Ingress×1, Job×1, Namespace×1,
 NetworkPolicy×8, PodDisruptionBudget×7, Service×12, ServiceAccount×6,
 StatefulSet×6)
```

Both clean. What's genuinely still true and unchanged: a real `helm
install` against a real Kubernetes cluster remains unattempted — no
cluster is available in this verification environment, and `helm
lint`/`template` passing is not the same claim.

Corrected: `docs/PRODUCT_STATUS_AND_V2_PREVIEW.md`'s "Tooling/environment
gaps" section, `PROGRESS.md`'s Part 3.2 checklist item.

## Why this matters beyond the two individual corrections

Both claims had sat uncorrected across several milestone cycles (KKKK's
coverage-gap assessment explicitly re-checked
`docs/PRODUCT_STATUS_AND_V2_PREVIEW.md` and found "no material
inaccuracies" — meaning a environment/tooling claim like this is exactly
the kind of thing a text-only re-read won't catch; it needed someone to
actually try the command again). The lesson carried forward: environment/
tooling gaps recorded in status docs have a shelf life the same way
integration claims do, and deserve the same periodic live re-check
CLAUDE.md § F requires for component-pair claims, not a one-time note
that's assumed durable.

## Status

No code changes this cycle — pure documentation-accuracy correction,
each backed by a real, captured command run above.

## Recommendation for the next cycle

1. Continue the RBAC/coverage thread's remaining open items: intake-retry
   test-stack CI-wiring (host memory), `add_case_member`/`remove_case_member`'s
   unvalidated `userId`.
2. Real GHA-runner verification (Milestone RRR's own open item) remains
   the one gap this correction pass can't close locally — it needs an
   actual `workflow_dispatch` or merge-to-`main`, not another local
   re-check.
