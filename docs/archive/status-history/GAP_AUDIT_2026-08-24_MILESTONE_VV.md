# Gap Audit — Milestone VV (2026-08-24)

Continuation of the JJ-UU gap-audit chain (docs/GAP_AUDIT_2026-08-24_MILESTONE_UU.md).
This pass covered the three named, never-audited adapter-layer candidates.

---

## 1. `cosign_verifier.py`: could raise past its own documented port boundary — FIXED

**Finding.** `CosignPackSignatureVerifier.verify()`'s two temp-file writes
sat outside the `try/except (OSError, subprocess.TimeoutExpired)` block —
a real `OSError` during setup (e.g. a full disk) escaped `verify()`
uncaught, violating the class's own documented contract (its own test
suite's docstring: "fail closed on any tool error, never raise past the
port boundary") and silently skipping the
`RULE_PACK_SIGNATURE_REJECTED`/`YARA_RULE_PACK_SIGNATURE_REJECTED` audit
event entirely, since neither caller (`RulePackService`/
`YaraRulePackService.import_signed_pack()`) has its own try/except around
this call. Confirmed empirically by patching `Path.write_bytes` to raise
`OSError` before fixing.

**Fix.** Moved both writes inside the existing try block. New regression
test confirmed to fail against the pre-fix source via `git stash`.
Committed as `9c4b34e`.

---

## 2. `admin_client.py`: `list_user_sessions()` lacked `list_organizations()`'s own defensive parsing — FIXED

**Finding.** `list_organizations()` already wraps its per-entry dict
access in `try/except (KeyError, ValueError)`, raising a clean
`KeycloakAdminError` on a malformed entry (proven by its own existing
test). Its sibling `list_user_sessions()` — the identical "iterate an
admin API list response" shape — had no such guard, so a session entry
missing `id`/`userId`/`username` raised a bare `KeyError` instead. Not a
security bug (a real Keycloak session always has these fields), but a
real observability/consistency gap on the method backing the real,
destructive session-revocation containment flow, where a confusing raw
exception in the audit trail matters more than most call sites.

**Fix.** Mirrored `list_organizations()`'s own try/except pattern. New
regression test confirmed to fail against the pre-fix source (raw
`KeyError: 'userId'`) via `git stash`. Committed as `29ca105`.

---

## 3. `local.py` reviewed, no gap

Test-only scaffolding (`LocalEvidenceStorage`, explicitly "Never use in
production"). Correctly implements the `EvidenceStorage` interface with
no dependencies beyond the local filesystem. No issue found.

---

## 4. `sealed_batch_storage.py`/`s3.py`: `_ensure_bucket()` never re-verifies Object Lock configuration on an already-existing bucket — REAL FINDING, NOT FIXED THIS PASS (needs live-MinIO PoC first)

**Finding.** `S3SealedBatchStorage._ensure_bucket()`'s docstring states it
"reuses the exact real mechanism `S3EvidenceStorage` already proves
against real MinIO" — checked that claim by reading `S3EvidenceStorage
._ensure_bucket()` directly, and found both classes share the exact same
structural gap:

```python
async def _ensure_bucket(self, bucket: str, ...) -> None:
    try:
        await self._run(self._client.head_bucket, Bucket=bucket)
        return                                    # <-- early return here
    except ClientError:
        pass
    # ... create_bucket(ObjectLockEnabledForBucket=True) ...
    # ... put_object_lock_configuration(...) ...   # <-- only reached on FIRST creation
```

If `head_bucket` succeeds (the bucket already exists), the method returns
immediately and **never checks or re-applies the Object Lock default
retention configuration**. This is only correct if bucket creation and
retention-rule application are guaranteed to always complete together as
one atomic unit — they are not: `put_object_lock_configuration` is a
*separate*, unguarded S3 API call after `create_bucket` succeeds, with no
try/except of its own (unlike `create_bucket`'s own handled
`BucketAlreadyOwnedByYou` race). Two real failure paths lead to the same
silent outcome:

1. A process crash (worker restart, OOM-kill) between `create_bucket`
   succeeding and `put_object_lock_configuration` completing.
2. A transient failure *of* `put_object_lock_configuration` itself (a
   real, plausible network blip against MinIO) — this raises uncaught out
   of `_ensure_bucket()`, so the caller's overall operation fails loudly
   on **that** attempt... but any retry of the same upload (automatic or
   manual) calls `_ensure_bucket()` again, sees `head_bucket` now succeed
   (the bucket exists from the partially-completed first attempt), and
   returns immediately — **never retrying the retention-configuration
   step, and never surfacing any error on the retry**.

In either case, the bucket is left with `ObjectLockEnabledForBucket=True`
at the bucket level but no default retention `Rule` — meaning newly
written objects get no automatic WORM protection at all, silently
defeating this platform's own explicitly stated "Key Decision: MinIO
Object Lock Compliance for evidence WORM enforcement." This is more
severe in `S3EvidenceStorage` (the primary evidence bucket) than in the
sealed-batch sibling, since evidence WORM retention is the platform's
core forensic-integrity guarantee.

**Why not fixed this pass.** A correct fix needs to distinguish two very
different states on an *existing* bucket — (a) Object Lock enabled at
creation but missing its default retention rule (recoverable: re-apply
`put_object_lock_configuration`), versus (b) a bucket that was never
created with `ObjectLockEnabledForBucket` at all (unrecoverable
retroactively — S3/MinIO's own API constraint, would need operator
intervention) — and the real response shape of `get_object_lock_configuration`
for each case has not been verified against the real, pinned MinIO
version this repo runs. Per CLAUDE.md §F ("no integration may be
described as working unless actually run against the real dependency"),
guessing at this distinction and shipping an unverified fix to the
*primary evidence storage* class is exactly the failure mode that section
exists to prevent — this is a real, live MinIO container
(`docker-minio-1`) already available in this dev stack, so the correct
next step is a dedicated `poc/` pass against it, not a guessed fix.

---

## Recommendation for the next wake-up cycle

**Priority 1 (this pass's own significant finding):** build a real PoC
against the live `docker-minio-1` container reproducing both bucket
states (object-lock-enabled-no-retention-rule, and no-object-lock-at-all),
capture `get_object_lock_configuration`'s real response shape for each,
and only then fix `_ensure_bucket()` in **both** `s3.py` and
`sealed_batch_storage.py` to verify (not assume) an existing bucket's
retention configuration, distinguishing the recoverable case (re-apply the
missing rule) from the unrecoverable one (fail loudly, do not silently
proceed as if WORM-protected). This is squarely a CLAUDE.md §F item —
follow that section's process exactly.

Also open, lower priority:
1. The lower-value optional SIEM/EDR secrets
   (`splunk_hec_token`/`sentinel_client_secret`/`defender_client_secret`)
   confirmed to degrade safely with `secrets_dir` but not yet moved off
   plaintext `environment:` in `docker-compose.prod.yml`.
2. Keycloak's own `KC_DB_PASSWORD`/`KC_ADMIN_PASSWORD` — no native
   file-secret convention exists in Keycloak 26.x itself.
3. The Postgres sync-replica ops-policy decision
   (`docs/POSTGRES_MINIO_HA_RESEARCH.md` §1.6) remains open for the
   project owner.
4. (UX-focused, not this audit chain's charter) `AdminPage.tsx`'s
   `UserRow` role-change/remove-user mutations have no `onError` handling.
