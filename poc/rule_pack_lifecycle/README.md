# C3 · Rule-pack lifecycle: versioning, Cosign signing, custom CRUD, cost gate

Verifies `src/domain/rule_pack.py`, `src/application/rule_pack_service.py`,
`src/application/rule_pack_publisher.py`, `src/application/cost_gate.py`,
`src/adapter/opensearch/custom_rule_client.py`,
`src/adapter/opensearch/custom_rule_detector_provisioner.py`,
`src/adapter/signing/cosign_verifier.py`, and
`src/adapter/repository/postgres_rule_pack.py` against the real, live
dev-stack OpenSearch 2.11.1 Security Analytics plugin, real PostgreSQL, and
a real, pinned Cosign binary.

## Versions pinned

- OpenSearch 2.11.1 (same cluster A1-C4 verified against).
- **Cosign v3.1.2** — not previously used anywhere in this repo; this is
  the first real invocation. Installed to `~/.local/bin/cosign` on the dev
  host for this verification pass (confirmed via `cosign version`, full
  output captured in `output.txt` Part 0).
- `pyyaml>=6.0` added to `pyproject.toml` for Sigma YAML parsing.

## Run

```
source ~/venv/bin/activate
python poc/rule_pack_lifecycle/run_poc.py
```

Requires the real dev stack up, a real `cosign` binary on PATH, and a
real signed bundle prepared once, out of band (not scripted — a rule-pack
*publisher* does this offline, not something KronOS itself ever does):

```
cosign generate-key-pair --output-key-prefix /tmp/cosign_poc_test/cosign
echo "hello rule pack content" > /tmp/cosign_poc_test/pack.bin
echo "tampered content" > /tmp/cosign_poc_test/pack_tampered.bin
cosign sign-blob --key /tmp/cosign_poc_test/cosign.key \
    --bundle /tmp/cosign_poc_test/pack.bundle /tmp/cosign_poc_test/pack.bin
```

## Result: 22 passed, 0 failed (see `output.txt` for the full real run)

## Real findings from building this

1. **A real Sigma rule's `logsource` block is product/service
   (zeek-style), not a bare `category` field.** OpenSearch's own rule
   category comes from the `?category=` query param on
   `POST _plugins/_security_analytics/rules`, not from anything inside
   the Sigma YAML. A rule missing `description`/`author`/`references`/
   `falsepositives` reproduces the exact real 500 `NullPointerException`
   documented in `custom_rule_client.py`'s docstring — confirmed directly,
   not assumed, by trial and error against the live cluster before the
   PoC's fixture rules were finalized.
2. **OpenSearch's own custom-rule API accepts a genuinely expensive rule
   shape (`|contains`, a leading-wildcard compile target) with zero
   validation or warning** — confirmed by actually pushing one directly
   (Part 1). This is the real, concrete justification for why
   `RuleCostGate` has to exist and run client-side, before a rule is ever
   handed to OpenSearch at all.
3. **Cosign v3.1.2's `sign-blob --bundle` produces a self-contained JSON
   bundle** (with an embedded Rekor transparency-log inclusion proof), not
   the bare detached `.sig` file older Cosign docs describe — confirmed by
   actually running `cosign version` and `sign-blob`/`verify-blob` against
   real content, not assumed from documentation. `verify-blob` correctly
   accepts the valid bundle over the original content and rejects the same
   bundle over tampered content bytes (a real signature mismatch, not a
   mocked check).
4. **A custom rule's OpenSearch-assigned `_id` is independent of the
   Sigma YAML's own `id:` field** — confirmed by round-tripping a rule
   with a fixed UUID `id:` and observing a different server-generated `_id`
   returned. `CustomRule.opensearch_rule_id` correctly stores the real
   server-assigned id, never the YAML's own declared one.
5. **The same real OpenSearch 2.11.1 PUT-update defect C2 found
   (`kotlin.collections.EmptyMap cannot be cast to
   kotlin.collections.MutableMap`) reproduces identically for a custom-rule
   detector.** `SecurityAnalyticsCustomRuleDetectorProvisioner` is a
   deliberate sibling to `SecurityAnalyticsDetectorProvisioner` (C2), not an
   extension of it, specifically to keep C2's already-verified
   check-then-create-only detector untouched while giving custom-rule
   detectors (whose content genuinely changes on every CRUD op, unlike C2's
   static prepackaged set) their own delete-and-recreate idempotency
   strategy.

## What Part 0/1 prove (cost gate + real OpenSearch behavior)

- A genuinely reasonable exact-match rule is accepted; a `|contains` rule
  and an unanchored `|re` rule are both rejected, each with a specific,
  real reason naming the actual compiled-query shape (not a generic
  "looks risky").
- OpenSearch itself accepts the expensive `|contains` rule with no
  rejection — confirmed by actually creating and then deleting it via the
  real API, proving the gate is genuinely necessary, not defensive
  guessing.

## What Part 2 proves (versioned CRUD, real Postgres)

- Adding a rule creates version 1; adding a second (cost-gated) rule
  creates version 2 with 2 rules total — version 1 remains independently
  retrievable and unchanged (`list_versions` returns both, real proof
  creating v2 never lost v1).
- The cost-gated rule is stored (never silently dropped) but correctly
  excluded from `accepted_rules`.

## What Part 3 proves (real Cosign signature gate)

- A validly-signed pack is accepted: `signature_verified=True`, a real
  `content_sha256` recorded, tagged `SIGNED_THIRD_PARTY`.
- The same bundle over tampered content bytes is rejected wholesale by
  the real Cosign verify-blob call — the import fails closed with
  `RulePackError`, and the rejected pack has **no version at all** (not a
  version with zero rules — the whole operation is refused before any
  bookkeeping happens).

## What Part 4 proves (publish + real tenant-scoped detector)

- Only the accepted rule is published to OpenSearch (the cost-gated one
  never reaches it); a real custom-rule detector is created, scoped to
  `kronos-{org_alias}-*` — this PoC's own synthetic org, never anything
  read from rule/pack content (Sigma has no field to express an index or
  tenant at all).
- Re-publishing is idempotent (0 newly published on a second call).
- The real detector and real custom rule this PoC created are deleted at
  the end (confirmed 0 leftover of each via a direct post-run query); the
  real Postgres `RulePack`/`RulePackVersion` rows are deliberately left as
  inspectable proof of the run, matching `poc/detection_finding_sync/`'s
  convention.

## Scope note (synthetic org, not kronos-dev)

This PoC deliberately uses a fresh synthetic org alias, not the dev
stack's real `kronos-dev` org. `kronos-dev` has ~40 legacy case indices
with inconsistent field mappings that trip OpenSearch SA's cross-index
alias-consistency check on **any** org-wildcard detector — a data-quality
artifact of that org's own PoC history (documented in
`poc/detector_provisioning/README.md`, C2), not a defect in this rule-pack
mechanism. Proving the mechanism clean against a synthetic org here
mirrors exactly how C2's own Part 1 established the same thing.
