# E4 · YARA rule-pack lifecycle: signed, versioned, published

Verifies `src/domain/yara_rule_pack.py`,
`src/application/yara_rule_pack_service.py`,
`src/adapter/repository/postgres_yara_rule_pack.py`,
`src/adapter/signing/cosign_verifier.py` (reused unchanged from C3), and
`src/application/yara_rules.py`'s `SignedYaraRulePackProvider` +
`yara_scan_org_var` against the real, live dev-stack PostgreSQL, a real
pinned Cosign binary, and — end to end — the real, completely unmodified
`ZipArchiveParser.extract_artifacts()` (roadmap E3) + `YaraXSandboxRunner`
(roadmap E2).

## Versions pinned

- Postgres: `docker-postgres-1` (`postgres:16-alpine`), same container
  every other PoC in this session uses.
- **Cosign v3.1.2** — already installed at `~/.local/bin/cosign` from C3's
  own session (confirmed below via `cosign version`); reused unchanged,
  not reinstalled/re-pinned.
- `yara-x==1.19.0` (`pyproject.toml` pin), via the real, unmodified
  `YaraXSandboxRunner`/`docker/yara/kronos-yarax-worker.py` (roadmap E2).

## Run

```
source ~/venv/bin/activate
python poc/yara_rulepack_lifecycle/run_poc.py
```

Requires the real dev stack up, a real `cosign` binary on PATH, and a real
signed bundle prepared once, out of band (mirrors
`poc/rule_pack_lifecycle/`'s own precedent — a rule-pack *publisher* signs
offline, not something KronOS itself ever does):

```
mkdir -p /tmp/cosign_poc_yara
cat > /tmp/cosign_poc_yara/yara_pack_content.bin <<'RULE'
rule Finds_Evil_Marker_E4Poc
{
    meta:
        author = "kronos-e4-poc"
        description = "Detects EVIL_MARKER_STRING used by the E4 PoC"
    strings:
        $marker = "EVIL_MARKER_STRING"
    condition:
        $marker
}
RULE
echo "tampered content, not what was signed" > \
    /tmp/cosign_poc_yara/yara_pack_content_tampered.bin
COSIGN_PASSWORD="" cosign sign-blob --yes \
    --key /tmp/cosign_poc_test/cosign.key \
    --bundle /tmp/cosign_poc_yara/yara_pack.bundle \
    /tmp/cosign_poc_yara/yara_pack_content.bin
```

This reuses the SAME `cosign.key`/`cosign.pub` key pair
`poc/rule_pack_lifecycle/` already generated at `/tmp/cosign_poc_test/` in
this session — not regenerated: a signer's key identity is the same
real-world artifact regardless of whether the content being signed is a
Sigma pack or a YARA pack.

## Result: 22 passed, 0 failed (see `output.txt` for the full real run)

Independently re-confirmed with raw SQL against the real tables after the
run (not just the script's own asserted checks):

```
$ docker exec docker-postgres-1 psql -U kronos -d kronos -c \
    "SELECT pack_id, version, source_tier, signature_verified, \
     jsonb_array_length(rules::jsonb) AS rule_count \
     FROM yara_rule_pack_versions ORDER BY created_at;"

               pack_id                | version |    source_tier     | signature_verified | rule_count
--------------------------------------+---------+--------------------+---------------------+------------
 e715a7d8-... (custom-pack)           |       1 | tenant_custom       | f                    |          1
 e715a7d8-... (custom-pack)           |       2 | tenant_custom       | f                    |          2
 d93ac571-... (signed-pack)           |       1 | signed_third_party  | t                    |          1
 abaa5353-... (scan-pack)             |       1 | tenant_custom       | f                    |          1
(4 rows)
```

Notably **`tampered-pack` has zero rows** in `yara_rule_pack_versions` —
the rejected import never reached bookkeeping at all, matching C3's own
"fails closed before any version is created" behavior exactly. And
`yara_rule_pack_published` has exactly 2 rows (`custom-pack` v2,
`scan-pack` v1) — `signed-pack` v1 was created but never published, so it
correctly does not appear there and never leaked into
`SignedYaraRulePackProvider.get_rule_source()`.

## What Part 0 proves

Real, captured `cosign version` output confirms v3.1.2 — the exact same
binary/version C3 already verified, not re-pinned or guessed.

## What Part 1 proves (versioned CRUD, real Postgres)

Adding a rule creates version 1; adding a second rule creates version 2
with both rules — version 1 remains independently retrievable and
unchanged (real proof creating v2 never lost v1, roadmap invariant #6).
`org_id` on every version is the real tenant's `TenantContext.org_id`,
never anything content-derived.

## What Part 2 proves (real Cosign signature gate — the SAME verifier C3 uses)

- A validly-signed pack is accepted: `signature_verified=True`, tagged
  `SIGNED_THIRD_PARTY`, and a real `content_sha256` recorded matching the
  actual signed bytes.
- The identical bundle over **tampered** content bytes is rejected
  wholesale by the real `cosign verify-blob` call — `import_signed_pack`
  raises `RulePackError`, and the rejected pack has **zero versions at
  all** (not a version with zero rules — the whole operation refuses
  before any bookkeeping happens, exactly mirroring C3's own Part 3
  finding for Sigma packs).
- **No new signature-verification code was needed.** `CosignPackSignatureVerifier`
  (`src/adapter/signing/cosign_verifier.py`) is genuinely generic —
  `verify(content: bytes, signature: bytes, public_key_path: str) -> bool`
  has no Sigma-specific assumption anywhere in its implementation (it
  shells out to `cosign verify-blob --bundle ... --key ... <content-file>`
  against whatever bytes it's given). This PoC is the first real
  confirmation that the exact same class, unmodified, correctly signs/
  verifies YARA rule-pack content — not just Sigma YAML.

## What Part 3 proves (publish pointer + org-scoped provider)

- Before `publish_version` is called, `SignedYaraRulePackProvider.get_rule_source()`
  correctly returns `None` even though a version with real rule content
  already exists — added-but-unpublished content must never leak into a
  live scan path (CLAUDE.md §A.6 "no silent side effects").
- After publishing, the provider returns the real concatenated rule text
  of the published version — proving the pointer mechanism
  (`yara_rule_pack_published`, a genuinely mutable upsert table, distinct
  from the immutable `yara_rule_pack_versions` rows it points into) works
  against real Postgres.
- A **second, unrelated org's** bound context (`yara_scan_org_var`) sees
  `None` from the same provider instance — real proof the org isolation
  invariant holds (CLAUDE.md §G.3: org scoping always from
  `TenantContext`, never leaking across tenants).
- No bound org context at all (`yara_scan_org_var.get() is None`) also
  correctly returns `None` — an honest "no context" state, not a crash or
  a fallback default ruleset.

## What Part 4 proves (the full real chain, end to end)

The concrete integration point this whole item exists to deliver: a real
zip evidence file's `evil.bin` member (containing `EVIL_MARKER_STRING`) is
scanned by the real, **completely unmodified**
`ZipArchiveParser.extract_artifacts()` — zero changes to that class or
`TarArchiveParser` were needed (per E3's own docstring's forward-looking
promise) — using rule text sourced through `SignedYaraRulePackProvider`
instead of `DirectoryYaraRuleProvider`, via the real `YaraXSandboxRunner`
subprocess (real `yara_x` Rust extension, real worker script). The
resulting `StructuredArtifact(kind="yara.match")` correctly names the
published rule (`Finds_Evil_Marker_E4Poc`), the correct `source_path`
(`evil.bin`), and the real tenant's `org_id` — never anything read from
pack/rule content.

## Design decisions this PoC confirms in practice

1. **No cost/DoS gate for YARA rule packs (see
   `src/domain/yara_rule_pack.py`'s module docstring for the full
   reasoning).** C3's `RuleCostGate` exists because a bad Sigma rule
   compiles to an expensive query against a *shared, multi-tenant
   OpenSearch cluster* — an amplifying, cluster-wide risk. YARA-X rulesets
   have no such shared-resource path: `YaraXSandboxRunner` already runs
   every scan in a sandboxed subprocess that is wall-clock-bounded two
   ways (in-worker `Scanner.set_timeout()` +
   `YaraXSandboxRunner`'s own outer subprocess timeout,
   `src/external/sandbox/yara_x_runner.py`'s
   `_SUBPROCESS_TIMEOUT_MARGIN_SECONDS`) — a genuinely existing, already-
   verified (this session's own `poc/yarax_sandboxed_runner/`) mitigation
   for the analogous risk shape. Building a parallel static-heuristic gate
   here would duplicate a real mitigation that already exists for a risk
   YARA-X scanning does not actually have.
2. **No new `PackSignatureVerifier` implementation was needed.** Confirmed
   directly above (Part 2) — `CosignPackSignatureVerifier` is reused
   completely unchanged.
3. **`yara_scan_org_var` (a `ContextVar`), not a new argument on
   `get_rule_source()`.** `YaraRuleProvider.get_rule_source()`'s signature
   is zero-argument by contract (so `ZipArchiveParser`/`TarArchiveParser`
   never need to change), yet a signed/versioned pack is inherently
   org-scoped. `ParsingOrchestrationService.execute_parse` binds this
   `ContextVar` to `tenant.org_id` around its own (already-existing) call
   to `extract_artifacts()` — the single call site for *every*
   `ForensicParser`, not just the two container ones — and resets it
   afterward. Verified for real in Part 3/4 above (both the "different
   org sees nothing" and "no context at all is None" cases), and by a
   dedicated unit test
   (`tests/unit/application/test_parsing_orchestration.py::TestExecuteParse::test_yara_scan_org_var_bound_around_extract_artifacts`)
   proving the bind/reset actually happens around the real orchestration
   call, not just inside this PoC's own manual `.set()`/`.reset()` calls.
4. **No HTTP route added.** C3 itself never got a route either — the
   Postgres search confirms zero references to `RulePackService`/
   `RulePackPublisher` anywhere under `src/external/routes/`, only DI-level
   FastAPI dependency functions (`get_rule_pack_service`,
   `get_rule_pack_publisher` in `src/external/dependencies.py`). E4 mirrors
   that exact scope: `get_yara_rule_pack_service`/
   `get_yara_rule_pack_repository` DI accessors exist, ready for a future
   route, but building one now would be scope beyond what C3 itself
   shipped.

## Real, honest gap found while wiring this (not glossed over)

Neither `docker/Dockerfile` nor `docker/Dockerfile.plaso-worker` `COPY`s
`docker/yara/kronos-yarax-worker.py` into the built image — unlike
`docker/plaso/kronos-plaso-worker.py`, which `Dockerfile.plaso-worker`
explicitly `COPY`s in. This means `YaraXSandboxRunner`'s default worker
path would **not** resolve inside a real deployed container today. This
PoC still runs the real worker successfully because it executes directly
from the repo checkout (`docker/yara/kronos-yarax-worker.py` is a real
file on disk here), not from a built container — so this is a real,
previously-undiscovered gap in E2/E3's own production activation, found
while deciding whether `src/external/startup.py::wire_dependencies_async`
should wire `_yara_runner`/`_yara_rule_provider` into
`configure_dependencies()` for E4. It deliberately was **not** wired
there this pass — doing so unverified against the real built container
image would itself violate CLAUDE.md §F ("plausible code without a
captured real run is an automatic fail"). Persistence wiring
(`PostgresYaraRulePackRepository` + `create_tables()`) *was* added to
`wire_dependencies_async`, since that part is independently real and
verified above. The Dockerfile `COPY` fix + a real container-level PoC
re-run is the concrete follow-up for whoever completes E2/E3/E4's actual
production activation.
