# Gap Audit — Milestone ZZ, round 2 (2026-08-25)

Continuation of round 1 (docs/GAP_AUDIT_2026-08-25_MILESTONE_ZZ.md). Traced
the three scenarios that round left queued. All three came back clean, but
each required real tracing (not a surface read) to rule out -- documenting
the reasoning since two of them looked plausible enough to be worth a real
investigation before being dismissed.

---

## Scenario 6: `RedisTicketStore`'s string-concatenation comparison vs. `InMemoryTicketStore`'s field-by-field comparison

**Suspicion.** `RedisTicketStore.consume()`/`put()` (`src/external/
middleware/step_up_store.py`) store/compare `f"{user_id}|{operation}|
{resource_id}"` as one opaque string, while `InMemoryTicketStore` compares
`user_id`/`operation`/`resource_id` as three separate fields. `operation`/
`resource_id` are free-text, client-supplied strings up to 128 chars with
no charset restriction (`StepUpTicketIn`, `src/external/routes/step_up.py`)
-- exactly the shape of a classic delimiter-injection bug, and structurally
the same *class* of bug (a ticket minted for one resource authorizing a
different one) that Milestone JJ already found and fixed once via a
different mechanism.

**Trace.** Worked the string algebra through concretely rather than
pattern-matching on "looks like a delimiter bug": for a real collision, an
attacker-chosen `(operation, resource_id)` pair at MINT time would need to
produce the exact same concatenated string as the REAL `(action_name,
resource_id)` pair used at CONSUME time. Consume-time `action_name` is
always one of a small set of fixed code literals (e.g.
`"revoke_keycloak_session"`) that never themselves contain a `|`, and
consume-time `resource_id` for the one real containment action
(`RevokeKeycloakSessionAction`) is a genuine Keycloak-generated session
UUID, also pipe-free. Because `|` is a literal, additive character (not an
escapable/invisible one), any extra `|` an attacker embeds in their own
mint-time `operation`/`resource_id` strictly increases the total pipe-count
of the resulting string relative to a real, pipe-free consume-time string
-- so the two can never collide as raw strings. Additionally confirmed a
second, independent layer: `RevokeKeycloakSessionAction._perform()`
re-verifies the presented `session_id` against Keycloak's own real,
live `list_user_sessions()` result before ever calling `revoke_session()`
-- even a hypothetically malformed `session_id` that survived the approval
gate would still be rejected here. **Not exploitable with any real caller
today** -- correctly ruled out after doing the actual character-count
argument, not assumed clean from the "looks fine" side either. Not fixed:
CLAUDE.md's own "don't add validation for scenarios that can't happen"
applies -- there is no live path that reaches this with an adversarial
value, and the two ticket-store backends are already required to satisfy
the same ABC contract only for currently-real inputs.

## Scenario 7: a revoked Keycloak session's already-issued JWT access token is still accepted

**Suspicion.** `RevokeKeycloakSessionAction` revokes a Keycloak *session*,
but `keycloak_auth.py::KeycloakTokenValidator.validate_and_extract()` only
checks JWT signature/issuer/audience/expiry -- no revocation-list or
introspection call. A revoked session's already-issued access token would
still pass every check this validator performs until its own `exp` claim.

**Trace.** Confirmed no revocation check exists anywhere in the token
validation path. This is real, but it is the well-understood, universally
accepted tradeoff of stateless JWT authentication (checking a revocation
list/introspecting on every request would mean a network round-trip per
request, contradicting CLAUDE.md §B.6's own `<500ms p95`/no-blocking-ops
baselines, and defeats the entire point of a self-contained bearer token).
The real, bounded mitigation is token lifetime:
`docker/keycloak/kronos-realm.json` pins `accessTokenLifespan: 900` (15
minutes) -- so the exposure window after a `revoke_keycloak_session`
containment action is a hard-capped ≤15 minutes, not indefinite. **Not a
coding defect** -- an architectural property inherent to any stateless-JWT
system, already bounded by a real, deliberately short-lived realm setting.
Not fixed/flagged as a gap: there is no reasonable code-level fix that
doesn't reintroduce the exact per-request latency/availability-coupling
this codebase's own performance baselines rule out.

## Scenario 8: a `SealedBatch`'s Merkle proof for event N becomes invalid/inconsistent after a dead-lettered event M (M != N, same batch) is later corrected and reprocessed

**Suspicion.** `DeadLetterEvent` preserves a failed-to-normalize event's raw
bytes for later manual correction/reprocessing. Checked whether reprocessing
a dead-lettered event could retroactively change anything the batch's own
frozen `merkle_root`/`leaf_hashes` depend on, breaking the "any single event
stays independently provable" guarantee `SealedBatch`'s own docstring
promises.

**Trace.** `BatchSealingService` (`src/application/batch_sealing.py:221`)
computes `leaf_hashes = [hashlib.sha256(m.payload).hexdigest() for m in
messages]` -- the SHA-256 of each event's raw bytes, at seal time, BEFORE
normalization (successful or failed) ever runs. `merkle_root` is built from
these raw-payload hashes. Reprocessing a dead-lettered event later re-runs
`StreamNormalizationService`'s normalizer against the *same* raw bytes
pulled back out of the WORM manifest (`DeadLetterEvent.payload`'s own
docstring: "the exact raw bytes decoded out of the sealed batch's WORM
manifest for this event_offset") -- normalization outcome (success or a
corrected re-run) never feeds back into `leaf_hashes`/`merkle_root`, which
are immutable fields on an already-frozen `SealedBatch` row. A Merkle proof
for any `event_offset` is therefore permanently reproducible from the
`SealedBatch` row alone, completely decoupled from whatever happens to that
event's normalization downstream. **Clean**, and confirmed exactly as
designed -- the domain layer's own "capture custody now, defer
interpretation" split (StructuredArtifact/DeadLetterEvent's shared
philosophy) does the real work here, not merely documented intent.

---

## Round 1 + 2 combined: 8/8 scenarios traced, all clean

This is a large enough sample (spanning tenant-isolation IDOR, mTLS
identity-spoofing, approval-ticket replay/delimiter injection, JWT
revocation timing, and cross-cutting data-integrity across the streaming
pipeline) to treat as a real signal, not noise: this codebase's
security-boundary and data-integrity logic specifically (as opposed to the
literal-constant/comment-drift class of bug the JJ-YY per-file review chain
kept finding) is in materially better shape. Recommending a strategy switch
for the next milestone rather than a third round of scenario-hunting on
diminishing-probability guesses:

1. **Return to "recently-landed, never-independently-reviewed" direct code
   review** -- the method CLAUDE.md's own Quick-Start section and this
   chain's early milestones (NN onward) established as reliably productive
   long after the audit-doc well ran dry. Candidate: `git log` for the
   newest feature commits not yet covered by a dedicated gap-audit
   milestone specifically (cross-check against every `GAP_AUDIT_*.md` this
   repo already has).
2. Alternatively, pick up one of the long-standing project-owner-decision
   items (Postgres sync-replica ops-policy, SIEM/EDR plaintext secrets,
   Keycloak's own admin/DB password file-secret gap) since those are real,
   named, and simply waiting rather than requiring new discovery work.
3. Check the CronCreate job (`0b6703d2`, created 2026-08-23) for re-arm
   next cycle -- it will be ~4 days old by then, still inside the safe
   window but worth planning the re-arm before it becomes urgent.
