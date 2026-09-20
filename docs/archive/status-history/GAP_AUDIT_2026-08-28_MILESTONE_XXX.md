# Gap Audit — Milestone XXX (2026-08-30)

**Scope:** the fourth multi-scenario subagent assessment (security/
CI-reliability/coverage-gap — same pattern as Milestones EEE, KKK+LLL,
PPP, TTT) run against Milestones UUU, VVV, and WWW's landed work — three
implementation-focused cycles that had landed since Milestone TTT with no
independent cross-check. One HIGH-severity, concrete, production-impacting
finding fixed and verified; the rest documented for upcoming cycles.

---

## Fixed this cycle

### `docker-compose.prod.yml` had no `celery-worker-plaso` — `q.parse.plaso` had zero consumer in production (CI-reliability review's own HIGH finding)

The single most consequential finding across all three assessment reports.
`ParserType.HEAVY` (`PlasoParser`, `ZipArchiveParser`/`TarArchiveParser`'s
container recursion, `VolatilityModule`) always routes to `q.parse.plaso`
(`src/external/celery_app.py`). `docker-compose.prod.yml`'s existing
`celery-worker` service only ever consumed `-Q
q.parse.fast,q.index,q.intake` — confirmed by reading the file directly,
not inferred. This is the exact same class of bug Milestone MMM found for
`q.intake` in `docker-compose.test.yml`, and Milestone UUU found (and
fixed) for `q.parse.plaso` in that same test-profile file — it was simply
never carried through to `docker-compose.prod.yml`, the one profile that
actually matters for a real deployment. Every HEAVY-tier upload in a real
production deployment of this repo would have sat in
`RECEIVED`/`PARSING` forever, silently, with zero error — precisely the
failure mode Milestones UUU/VVV/WWW's own "HEAVY-tier is now covered"
claims never actually addressed, because all three cycles verified against
`docker-compose.test.yml`/`.dev.yml` only.

**Deeper than a missing compose block**: `.github/workflows/build.yml`
never built, scanned, signed, or published an image from
`docker/Dockerfile.plaso-worker` at all — only `docker/Dockerfile` (the
plain backend). So even after adding the compose service, there was no
real image anywhere for it to reference. Fixed both halves together:

1. `build.yml`'s `trivy-scan` and `push-image` jobs converted to a
   `strategy: matrix` over `{backend, plaso-worker}` (not a duplicated
   second job — one definition, so a future third image variant is a
   one-line `include:` addition, not copy-pasted YAML). Both images now go
   through the identical build → Trivy scan (gated on CRITICAL/HIGH) →
   SBOM → Cosign sign → Cosign attest pipeline. Trivy SARIF uploads are
   now `category`-tagged per image so both appear distinctly in the
   Security tab instead of one silently overwriting the other.
2. `docker-compose.prod.yml` gets a new `celery-worker-plaso` service,
   referencing the new `ghcr.io/.../plaso-worker:${IMAGE_TAG:-latest}`
   image. Field-for-field mirrors `celery-worker`'s own already-audited
   required-`Settings` set (confirmed via `celery_app.py` instantiating
   `Settings()` at import — any celery worker needs the full required
   set or it crashes on boot, not just the fields its own queue happens
   to touch) rather than mirroring dev's more liberal, less-audited
   style. `CLAMD_HOST`/`CLAMD_PORT` included even though this worker never
   itself runs `process_intake`'s scan step — confirmed by reading
   `configure_clamav_from_settings()`
   (`src/external/dependencies.py`) directly: it runs unconditionally at
   *every* celery worker's startup and hard-fails boot in production if
   clamd is unreachable (EVID-6), not queue-specific. `TSA_URL`
   deliberately omitted, matching `celery-worker`'s own existing choice
   (confirmed via grep: no RFC3161/TSA usage anywhere in
   `parsing_orchestration.py`). `-c 1` concurrency and a 2 GiB memory
   limit (celery-worker's own limit is 1 GiB) — the higher limit is a
   judgment call grounded in this very cycle's own Milestone WWW PoC,
   which drove a real 512 MiB memory-forensics file through this exact
   worker shape.

**Verified, not assumed**: `docker compose -f docker-compose.prod.yml
config -q` passes clean (only a pre-existing, unrelated `version:` field
deprecation warning) with a full set of placeholder secrets/env vars
provisioned the same way `docker/secrets/README.md`'s own Path A
instructions describe; the resolved config was inspected directly
(`image`, `command`, `environment` keys, `secrets`, `depends_on`) to
confirm the new service matches `celery-worker`'s field set exactly, not
just that YAML parsing succeeded. `docker build -f
docker/Dockerfile.plaso-worker .` (repo-root context, the exact invocation
`build.yml`'s matrix now uses, not `docker-compose.test.yml`'s own
`context: ..` from the `docker/` subdirectory) confirmed to build
successfully — a real, distinct code path from what Milestone UUU had
already exercised via Compose, checked rather than assumed identical.
Both `.github/workflows/build.yml` and `docker/docker-compose.prod.yml`
pass `yaml.safe_load`.

## Assessment findings documented, not fixed this cycle

### Security: clean

No exploitable findings across UUU/VVV/WWW. The `POST /api/cases`
`BackgroundTasks` change (Milestone VVV) confirmed safe from a security
lens specifically: arguments captured by value at scheduling time (not
references to request-scoped state), both provisioners self-contained
with their own HTTP clients and admin-only credentials scoped correctly,
case creation's own audit event still fires synchronously before the
background tasks are scheduled. No hardcoded production credentials in
any of the three milestones' diffs; `poc/volatility_pipeline_ingest/`'s
captured output contains only UUIDs and a public, well-known
malware-analysis training sample's already-public metadata — no PII, no
tokens.

### CI-reliability: four smaller findings beyond the one fixed above

1. **[MEDIUM]** `timeout-minutes: 70`'s own justification comment cited
   the archive spec's "~35s measured cost," not its own declared
   worst-case `test.setTimeout` ceilings (150s + 180s = 330s combined) —
   a real methodology regression from the derivation discipline Milestone
   TTT established. The number itself likely still has margin; the
   *reasoning* documented for it doesn't currently match the spec's own
   declared ceilings. Fix: restate the comment citing the real 330s
   figure, matching how the two fault-injection specs' ceilings are
   already cited.
2. **[MEDIUM]** `celery-worker-plaso`'s image build time is documented
   only as a lower bound ("still building when I stopped watching,
   locally, warm cache") — the single largest unmeasured input to the
   70-minute total. A cold GHA runner with no Chainguard-layer cache could
   take meaningfully longer.
3. **[LOW-MEDIUM]** The `BackgroundTasks` change means case creation is no
   longer naturally serialized the way an awaited call was — up to ~16
   concurrent background provisioning tasks could pile onto one backend
   process across the 9-step E2E job's ~8 case creations, competing for
   the same OpenSearch connection pool that caused the original 15s-
   timeout bug in the first place. Not caught by any spec since nothing
   asserts on dashboards/detector state after case creation.
4. **[LOW]** A case created near a CI step's end could still have an
   in-flight background task when `docker compose down` fires, injecting
   a stray cancelled-httpx traceback into the failure-log-capture
   artifact — cosmetic noise, not a real failure, but could distract
   whoever triages this job's first real GHA run.

### Coverage-gap: four real gaps named

1. **TarArchiveParser has zero CI-wired coverage** — WWW's "every
   HEAVY-tier parser has been driven through the real pipeline" claim
   rests on `poc/tar_container_unwrapping/`, a real, well-verified PoC
   that predates this initiative entirely and is never cited by name in
   UUU/VVV/WWW. Unlike Zip/EWF (Milestone VVV) and Volatility (WWW), Tar
   has no `frontend/e2e/*.spec.ts` and no CI workflow step. Cheap fix:
   the fixture-building script already exists; port to a spec + wire in,
   matching Milestone VVV's own archive-spec pattern.
2. **FAST-tier parsers are now the least-verified tier by comparison.**
   Of evtx/cloudtrail/nginx/suricata/chrome_history, only CloudTrail has
   a standalone browser E2E spec. Raw `.evtx` has never been uploaded as
   top-level evidence in any spec — only indirectly as an archive member.
   Three cycles focused on closing HEAVY-tier gaps inadvertently widened
   this asymmetry. This is the coverage-gap review's own top
   recommendation for the next cycle.
3. **Cross-tenant isolation is architecturally untestable for
   `StructuredArtifact` right now** — `verify_artifacts.py`
   (Milestone WWW) necessarily queries Postgres directly with a superuser
   DSN, filtered only by `evidence_id`, because no HTTP read API or authz
   layer exists yet for this domain object. Correctly deferred (no read
   API exists to test against), but worth a tracked TODO so the eventual
   read API's own test plan starts with tenant-scoping in mind, not as an
   afterthought.
4. **No spec exercises the immediately-after-case-creation window** the
   `BackgroundTasks` fix (Milestone VVV) newly introduced — previously
   case creation blocked until dashboards/detector provisioning finished;
   now a user opening Discover/Security Analytics within ~15s of creating
   a case could hit a missing index-pattern or detector where before it
   would already exist. A real, new (if narrow) UX race with zero
   coverage of the invariant it changed.

## Status

The one HIGH-severity, concretely actionable finding (production's own
`q.parse.plaso` blind spot, plus the missing image-publishing pipeline
that made a compose-only fix incomplete) is fixed and verified. Security
is clean across three cycles' worth of real changes. The remaining seven
findings (four CI-reliability, four coverage-gap — one CI-reliability
item overlaps with what got fixed) are all real but lower-severity or
correctly deferred, and are queued below rather than rushed.

## Recommendation for the next cycle

1. FAST-tier parser E2E coverage (coverage-gap review's own top pick) —
   cheap, existing fixtures, follows the CloudTrail spec's own pattern.
2. TarArchiveParser CI-wired coverage, porting the existing
   `poc/tar_container_unwrapping/` fixture into a spec.
3. Restate the `timeout-minutes: 70` justification comment to cite the
   archive spec's real 330s worst-case ceiling, closing CI-reliability
   finding #1 above (cheap, docs-only).
4. Intake-stage retry E2E coverage (carried since Milestone TTT).
5. If the immediately-after-case-creation race (coverage-gap finding #4)
   or the background-task-concurrency contention risk (CI-reliability
   finding #3) is ever observed for real, that's the signal to actually
   build a spec for it rather than pre-building one for a race not yet
   confirmed to matter in practice.
