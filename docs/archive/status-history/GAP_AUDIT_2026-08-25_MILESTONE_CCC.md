# Gap Audit — Milestone CCC (2026-08-25)

Per Milestone BBB's own recommendation: extended the "actually run it"
method into the production secrets/KMS infrastructure
(`docker/vault/`, `docker/kes/`, `docker/pki/`, and
`docker-compose.prod.yml`'s own inline Vault/KES wiring), which hadn't had
a dedicated real-execution check anywhere in the JJ-CCC chain.

---

## `docker-compose.prod.yml`'s Vault/KES chain was completely non-functional — three independent bugs found and fixed

**Method.** Brought up `vault`, `vault-init` (new), and `kes` from the real
`docker-compose.prod.yml` in an isolated `kronos-poc-vault-verify` project
(never touching the real running dev stack), reading real container logs
and real `docker inspect` health status at every step, rather than reading
the YAML and assuming it was correct.

**Bug 1 — `vault`'s healthcheck always failed.** `test: ["CMD", "vault",
"status"]` has no `VAULT_ADDR`, so the CLI defaults to
`https://127.0.0.1:8200` — but `VAULT_DEV_LISTEN_ADDRESS` means dev mode
always serves plain HTTP. Confirmed by actually running it: `Error
checking seal status: ... http: server gave HTTP response to HTTPS
client`, every single retry, container permanently `unhealthy`. Since the
pre-existing `kes` service already declared `depends_on: vault: {condition:
service_healthy}`, **this alone meant `kes` could never have started even
before any of its own bugs (below) were considered.** Fixed with the same
`VAULT_ADDR=http://localhost:8200` prefix already proven correct in
`docker/vault/docker-compose.vault.yml`'s own healthcheck — confirmed via
`docker inspect` that `vault` now genuinely reports `healthy`.

**Bug 2 — no `vault-init` step existed at all.** The transit engine was
never enabled, the `kronos-evidence` key never created, and the `kv`
engine + policy + AppRole role KES's own keystore backend needs (per
`docker/kes/kes-config.yml`'s already-corrected schema — see below) never
existed. Added a `vault-init` service, a verbatim copy of the real,
already-verified script from `docker/vault/docker-compose.vault.yml`
(itself proven end-to-end in `poc/vault_kes_minio/`, gaps #1/#2 of that
PoC's own README). Ran it for real: transit key created, `kv` engine
enabled, policy uploaded, `approle` auth enabled, `kronos-kes` role
created, exit code 0.

**Bug 3 — `kes` referenced a nonexistent host config file and a floating
image tag.** `image: minio/kes:latest` (a floating tag) bind-mounted
`./kes/config.yaml` — a host path that has never existed anywhere in this
repo (the real file is `./kes/kes-config.yml`, a completely different
name). Docker's real behavior for a nonexistent bind-mount source is to
silently create an empty directory at the mount point rather than fail —
confirmed directly (`docker run -v .../config.yaml:/etc/kes/config.yaml`
against a nonexistent host file produces a 4096-byte directory inside the
container, not an error) — so `kes server --config /etc/kes/config.yaml`
would fail trying to parse a directory as YAML. The second bind mount on
the same service, `./certs:/certs:ro`, also references a path
(`docker/certs/`) that does not exist anywhere in the repo. Fixed by
pinning the same real, already-verified image tag
(`minio/kes:2024-06-17T15-47-05Z`) and config file
(`./kes/kes-config.yml`) already proven correct in
`docker/kes/docker-compose.kes.yml`, and switching the certs mount to a
named volume (`kes_certs`) matching that same sibling file's own pattern,
instead of a phantom host directory.

**Verification, in increasing depth.**
1. `vault` up → healthy (confirmed via `docker inspect`).
2. `vault-init` run → real transit/kv/policy/approle setup, exit 0.
3. `kes` up (with default-empty `VAULT_APPROLE_ID`/`SECRET`) → failed with
   `Error: kesconf: invalid vault keystore: invalid approle config: no
   approle ID specified` — this is the config file now being *correctly
   parsed and semantically validated*, failing only on the next real,
   already-known gap (below), not on a garbage/directory config anymore.
4. To confirm the fix goes further than "reaches the next known error,"
   fetched the *real* AppRole role-id/secret-id live from `vault-init`'s
   own freshly-created role (`vault read auth/approle/role/kronos-kes/
   role-id`, `vault write -f .../secret-id`) and re-ran `kes` with them
   injected: it progressed cleanly past AppRole validation entirely and
   failed on a *different*, also-already-documented gap: `Error: failed to
   read TLS certificate: open /etc/kes/certs/server.crt: no such file or
   directory` (the named volume starts empty; nothing provisions certs
   into it). This is strong confirmation the fix is correct end-to-end up
   to the two genuinely-unsolved gaps below, not just superficially
   plausible.
5. All `kronos-poc-vault-verify`-prefixed containers/volumes/networks
   cleaned up (`down -v --remove-orphans`). The real running dev stack
   (`docker-compose.dev.yml`) was never stopped, restarted, or touched.

**Honestly NOT fully fixed — two gaps remain, neither solved anywhere in
this repo today, documented inline in the compose file itself rather than
silently implied as resolved:**
1. `VAULT_APPROLE_ID`/`VAULT_APPROLE_SECRET` still default to empty in the
   real `kes` service — nothing automatically fetches and injects the real
   role-id/secret-id the way this verification pass did by hand.
   `poc/vault_kes_minio/README.md`'s own gap #3 already named this as an
   open item; it remains open.
2. `kes_certs` starts empty — nothing provisions the real
   `server.crt`/`server.key`/`ca.crt` `kes-config.yml` requires, or the
   MinIO client cert its policy identity needs to match.
   `poc/vault_kes_minio/` generated a throwaway PKI by hand for its own
   one-off run; production needs a deliberately-designed, real issuance
   path, which is a genuine design decision (not merely a missing script),
   not attempted here.

Committed as `ae916c6`.

---

## `docker/pki/` — confirmed already-known-dormant, not a new finding

Checked `docker/pki/docker-compose.pki.yml` + `bootstrap.sh` (a standalone
step-ca-with-ACME-provisioners reference implementation) for the same
class of "never actually run" bugs. Before investing further verification
effort, checked whether this file is even wired into anything real: **it
is not** — `docker-compose.prod.yml` has zero step-ca references at all,
and `docker-compose.dev.yml`'s own step-ca service is a separate, simpler,
already-proven-working definition that does not use this bootstrap script.
`docker/init/tls-init-entrypoint.sh`'s own comment already documents this
explicitly: *"via its live 'admin' JWK provisioner (see
docker/init/Dockerfile.tls-init for why not the unwired docker/pki/
bootstrap.sh provisioners)"* — an earlier pass already found and routed
around whatever issues `docker/pki/`'s approach had, and documented the
decision. No new investigation needed; not touched.

## `docker/kes/` and `docker/vault/` themselves — confirmed already correct

Both standalone files (`docker-compose.kes.yml`, `kes-config.yml`,
`docker-compose.vault.yml`) already reflect every fix
`poc/vault_kes_minio/README.md` documented (gaps #1, #2, #4 all visibly
incorporated via their own inline comments citing that PoC). These were
the reference implementations used to fix `docker-compose.prod.yml`'s
independent, broken duplicate of the same services — not independently
re-verified from scratch in this pass, since the PoC's own real, captured
end-to-end run (`poc/vault_kes_minio/output.txt`) already proved the full
chain works when correctly configured.

---

## Recommendation for the next wake-up cycle

1. The two remaining Vault/KES gaps (AppRole credential auto-injection,
   TLS cert provisioning) are real engineering work, not quick fixes --
   worth a dedicated, deliberately-scoped milestone if picked up, following
   the same PoC-first discipline (a real automation script, verified
   end-to-end against live Vault, before touching `docker-compose.prod.yml`
   again).
2. This is now the third production-infra deployment blocker found this
   chain via real execution (TSA image, Vault healthcheck, KES config) --
   worth a full, dedicated pass attempting a complete, real
   `docker compose -f docker-compose.prod.yml up` (with all required env
   vars set to real or realistic values) end-to-end, rather than
   service-by-service, to find any remaining blockers systematically
   instead of one at a time.
3. Return to either a fresh scenario-tracing round or per-file review of
   an area not yet covered in JJ-CCC, if the production-infra vein runs
   dry after the above.
4. Check CronCreate job `0b6703d2` (created 2026-08-23, ~3 days old as of
   this pass) -- getting closer to the 5-6 day re-arm window, plan to
   re-arm within the next cycle or two.

Still open, unchanged from prior milestones: the docker-compose.prod.yml
TSA image gap (Milestone BBB, still undecided pending a project-owner TSA
vendor choice), the lower-value optional SIEM/EDR plaintext secrets,
Keycloak's own admin/DB password file-secret gap, the Postgres
sync-replica ops-policy decision, `AdminPage.tsx`'s missing `onError`
handling, `SecurityAnalyticsCorrelationRuleProvisioner._rule_name()`'s
truncation edge case, and `main`'s own frozen/failing CI state.
