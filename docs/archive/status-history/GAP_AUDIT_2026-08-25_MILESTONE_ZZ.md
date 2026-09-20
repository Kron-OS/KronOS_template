# Gap Audit — Milestone ZZ, round 1 (2026-08-25)

Per Milestone YY's own recommendation (docs/GAP_AUDIT_2026-08-25_MILESTONE_YY.md):
switching strategy away from a third consecutive per-file review pass to a
scenario-driven assessment (mirroring Task #14/#27) -- tracing concrete
end-to-end attack/misuse flows across routes+services+adapters, rather than
reading files in isolation.

This round traced five concrete scenarios to completion. All five came back
clean; documenting the trace itself (not just the verdict) since the value
of this exercise is in the chain of reasoning, and because a clean scenario
trace is real evidence to point future audits away from re-checking the
same ground.

---

## Scenario 1: cross-tenant read of another org's audit trail via `/api/audit/merkle-proof/{event_id}`

**Attack shape.** `event_id` is a client-supplied path parameter with no
inherent tenant scoping in the URL itself -- the classic IDOR shape.

**Trace.** `src/external/routes/audit.py::merkle_proof` does NOT do a
"fetch by id, then check org_id" pattern (which is easy to get wrong via a
missed check) -- it structurally cannot leak, because it only ever
searches within `audit_svc._repository.stream_by_org(tenant.org_id)`
(caller's own org only) for a matching `event_id`. An `event_id` belonging
to another org is never in that stream, so the lookup returns `None` and
the route 404s -- same response as a wholly nonexistent id, no timing or
information-disclosure gap. **Clean.**

## Scenario 2: cross-tenant read of another org's case audit trail via `/api/cases/{case_id}/audit`

**Attack shape.** A case-lead in org A tries to read org B's case audit
trail, or a case-lead in org A who doesn't own the specific case tries to
read a sibling case-lead's case in the same org.

**Trace.** `case_repo.get_by_id(case_id, tenant.org_id)` is already
org-scoped (404 if the case belongs to another org or doesn't exist), then
`assert_case_lead_or_admin(tenant, case)` enforces real case-ownership
(not just role name) for CASE_LEAD callers, then `stream_by_case(case_id,
tenant.org_id)` is called with both filters, plus a redundant
belt-and-braces post-filter (`if ev.org_id != tenant.org_id: continue`).
Three independent layers for the same invariant. **Clean** -- this route
already carries scars from two named prior fixes (AUTH-004, AUTH-007)
visible in its own comments.

## Scenario 3: a collector holding a valid mTLS cert for org A tries to smuggle org B's `org_id` into its own stream payload

**Attack shape.** POST a batch to `/api/collector/ingest` with a valid
cert (issued to org A) but an `org_id` field inside the JSON body claiming
org B.

**Trace.** `collector_ingest.py::ingest_events` never reads `body.events`
for org/source identity at all -- `identity: CollectorIdentity` (the sole
source of `org_id`/`source_id` for the whole batch) comes exclusively from
`get_collector_identity`, which reads the DER client cert placed on
`request.scope["extensions"]` by the mTLS transport layer
(`mtls_protocol.py`) during the TLS handshake -- before any application
code, let alone a JSON body, is parsed. `X509SanCollectorIdentityExtractor`
parses org_id/source_id only from the certificate's own URI SAN
(`urn:kronos:collector:org:<uuid>:source:<id>`), never from request
content. A forged body field is simply never read. **Clean.**

## Scenario 4: an ERROR-state evidence retry bypasses the intake/parse-stage routing or returns a misleadingly stale response

**Attack/confusion shape.** Two near-identical sibling routes
(`retry-intake`, `retry-parse`) -- checked whether they diverge in a way
that lets a terminal-reason evidence row get retried, or whether one
route's response is inconsistent with the other's in a way a client could
rely on incorrectly.

**Trace.** Both routes independently re-check `is_retryable_error_reason`
then the appropriate `is_parse_stage_error_reason` polarity server-side
(never trusting client-side gating alone), both correctly org-scope via
`evidence_repo.get_by_id(evidence_id, tenant.org_id)`. One real, asymmetric
detail found: `retry_intake`'s route returns the PRE-retry `Evidence`
object (still `state=ERROR`) in its response body, while `retry_parse`'s
route returns the POST-retry object (already `state=PARSING`) -- because
`ParsingOrchestrationService.retry_parse()` synchronously transitions the
FSM to PARSING and persists it before returning (a legitimate, real state
change that has already happened), whereas
`EvidenceIntakeService.retry_intake()` only enqueues a Celery task (or, in
the no-queue fallback, runs synchronously) and returns `None` --
the actual SCANNING transition genuinely has not happened yet inside the
HTTP request/response cycle for the queued path, so returning the old
object is factually accurate, not stale-by-mistake.

**Not a bug**, but worth recording: this WOULD be exploitable-by-confusion
if any caller trusted the retry-intake response body's `state`/`retryAction`
fields for anything. Checked the one real caller
(`frontend/src/components/EvidenceDetailDrawer.tsx`'s `retryMutation`):
`onSuccess` ignores the response body entirely and calls
`queryClient.invalidateQueries()` to force a real re-fetch -- consistent
with CLAUDE.md §E.2's "frontend's only responsibility after a
state-changing call is to wait for the real state via SSE/refetch, never
assume the synchronous response reflects final state." **Clean**, and
notably robust *because* of that architectural rule, not by accident.

## Scenario 5: a webhook-push `IntegrationSource` API key survives being provisioned, but does the real deployment actually persist it?

**Attack/regression shape.** Not an attacker-controlled scenario but a
"does the production wiring match the documented design" check --
`StaticApiKeyInboundAuthenticator`'s own docstring claims keys are queried
per-request from a `IntegrationSourceKeyRepository`, provisioned live via
an admin route with "no restart required." The default binding in
`dependencies.py` (`_integration_source_key_repository =
InMemoryIntegrationSourceKeyRepository()`) is process-local and would
silently make every provisioned key vanish on every backend restart if
real startup never swaps it for a persistent implementation.

**Trace.** Confirmed `src/external/startup.py:133` really does construct
`PostgresIntegrationSourceKeyRepository(engine)` and wires it in at real
process boot (not just available-but-unused) -- the in-memory default in
`dependencies.py` is only ever live in tests/before real startup runs.
`PostgresIntegrationSourceKeyRepository` (`src/adapter/repository/
postgres_integration_source_key.py`) exists as a real, separate class, not
a stub. Also verified `get_by_key()`'s revocation check
(`record.is_revoked` -> `None`) is present on the in-memory reference
implementation and mirrors the ABC's own documented contract. **Clean.**

---

## Recommendation for the next wake-up cycle

All five traced scenarios came back clean -- a genuinely different (and
reassuring) outcome than several per-file passes in the JJ-YY chain, which
each found at least one real drift/gap. This suggests the codebase's
*integration/security-boundary* logic (the specific thing scenario tracing
targets, as opposed to per-file correctness) is in materially better shape
than, say, frontend/backend literal-constant drift was. Two honest
readings, both worth acting on:

1. Continue this scenario-driven approach with a fresh batch of scenarios
   next cycle (candidates not yet traced: "an org-admin approval-ticket
   generated for one containment action is replayed against a different
   action/detection," "a revoked Keycloak session is still accepted by a
   cached JWT within its exp window," "a SealedBatch's Merkle proof for
   event N survives after a dead-lettered event M<N in the same batch is
   later manually corrected/replayed") -- since 5/5 clean is a small
   sample, not proof the technique has run dry.
2. In parallel, this is a reasonable point to re-arm the CronCreate job
   (`0b6703d2`, created 2026-08-23) with a fresh STATE AS OF section
   reflecting real tip `fcd91a1` and this task list -- it is not yet within
   its 7-day auto-expiry danger zone (~2 days old as of this pass) but the
   next wake-up cycle should check again and re-arm proactively rather than
   right at the deadline.

Still open from prior milestones, unchanged (see Milestone YY's doc for the
full list): SIEM/EDR plaintext secrets in `docker-compose.prod.yml`,
Keycloak's own admin/DB password file-secret gap, the Postgres sync-replica
ops-policy decision, `AdminPage.tsx`'s missing `onError` handling, and
`SecurityAnalyticsCorrelationRuleProvisioner._rule_name()`'s truncation
edge case.
