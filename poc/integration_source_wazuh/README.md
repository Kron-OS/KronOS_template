# PoC: Wazuh source connector (roadmap Q2) -- L2

**Objective.** Prove a real `wazuh-integratord` webhook, configured with a
real `<integration>` block, forwards a real Wazuh alert to KronOS's real
`IntegrationSource` PUSH endpoint end to end: real alert fires -> real
custom integration script -> real HTTP POST -> real
`POST /api/integrations/push/wazuh` -> real `StaticApiKeyInboundAuthenticator`
-> real `WazuhPushSource.parse_push_event` -> real
`IntegrationSourceIngestService.ingest_push` -> real dedup/backpressure ->
real `StreamIngestAdapter.produce` -> real audit event.

**Stage reached (roadmap SS3): test-stage only.** This PoC runs the real
KronOS FastAPI app + real `WazuhPushSource` inside a throwaway container
started directly with `docker run` (mirroring
`poc/integration_source_foundation/run_poc_push.py`'s own "real app, PoC-tier
in-memory storage doubles" bar), against a real, separately running Wazuh
manager container -- **not** wired into `docker-compose.dev.yml` itself
(dev-stage) or `docker-compose.prod.yml` (prod-stage). No concrete
`StaticApiKeyProvisioning` entry for a real customer's Wazuh manager exists
in `startup.py` yet either (same honestly-incomplete state Q1 itself
documented for its own foundation). Both are real, deliberate follow-up
work, not silently skipped.

## Pinned-version correction -- found and verified before building anything (CLAUDE.md SS F)

`docker/wazuh/docker-compose.wazuh.yml` pins `wazuh/wazuh-manager:5.1.0` and
says "Must use Wazuh >=5.1. Wazuh 5.0 has a silent data-destruction CVE."
Both the version and the fix-version referenced there turned out to be
wrong, verified 2026-08-09 against two independent real sources, not
assumed:

1. **`5.1.0` does not exist.** Docker Hub's real tag list for
   `wazuh/wazuh-manager` (`GET
   https://hub.docker.com/v2/repositories/wazuh/wazuh-manager/tags`, 65
   tags total) has no `5.1.x` tag at all -- the newest is `5.0.0-beta4`.
   The real Wazuh GitHub Releases API
   (`https://api.github.com/repos/wazuh/wazuh/releases`) confirms the same:
   the newest 5.x release is `v5.0.0-beta4` (prerelease), and the current
   real *stable* release is `v4.14.7` (published 2026-07-30).
2. **The CVE is real, but the fix landed earlier than "5.1".** It is
   GHSA-ff9g-85jq-r3g3, a CVSS-10 vulnerability in Wazuh 5.0's new
   `inventory_sync` subsystem (a malicious enrolled agent can inject
   arbitrary OpenSearch bulk operations via an unvalidated
   `DataValue.index` field), affecting `5.0.0-beta1`-`5.0.0-beta2`,
   **patched in `5.0.0-beta3`**. There is no `5.1` line at all, patched or
   otherwise.
3. **Separately, and more importantly for this specific connector: Wazuh
   5.x has already replaced the entire mechanism this roadmap item is
   about.** Directly inspecting a real, running `wazuh/wazuh-manager:5.0.0-beta4`
   container found:
   - Config file moved from `/var/ossec/etc/ossec.conf` to
     `/var/wazuh-manager/etc/wazuh-manager.conf`, root XML element renamed
     from `<ossec_config>` to `<wazuh_config>`.
   - Control binary renamed `wazuh-control` -> `wazuh-manager-control`.
   - **No `wazuh-integratord` binary exists anywhere in the image at all**
     (`find / -iname '*integrat*'` inside the running container found
     nothing under `/var/wazuh-manager/bin/`). Outbound alerting appears to
     have moved to a new, undocumented YAML-based "engine outputs" system
     (`etc/outputs/default/file-output-integrations.yml`, `enabled: false`
     by default) -- no public Wazuh documentation for this new mechanism
     exists yet as of 2026-08-09 (`documentation.wazuh.com/5.0/...` 404s).

Given this roadmap item is specifically, explicitly about
`wazuh-integratord`'s real `<integration>`-block mechanism, and that
mechanism has already been removed in the only available 5.x images, this
PoC (and `WazuhPushSource`) were built and verified against
**`wazuh/wazuh-manager:4.14.7`** (the current real stable release) instead
of either the nonexistent `5.1.0` or a 5.x beta whose relevant subsystem no
longer exists. `4.14.7` predates the `inventory_sync` subsystem entirely,
so the CVE this repo's comment is worried about does not apply to it either.
**Flagged for the orchestrator, not silently applied:** `docker/wazuh/docker-compose.wazuh.yml`
itself (image tags, volume paths under `/var/ossec/`) is dormant SIEM-side
infra config outside this connector module's own scope -- it needs a
version-pin + path fix given the findings above, but that decision belongs
to whoever owns that file, not this module's PR.

## Versions pinned (real, this pass)

- `wazuh/wazuh-manager:4.14.7` (see correction above) --
  `sha256:c364ef100ba40d501537b1668a5a72bba4c4fbcf39bbef6a02123ff221fc40d0`.
- `kronos-backend:dev` (this repo's own already-built dev image) as the
  Python/FastAPI/uvicorn/httpx runtime for the receiver half -- reused
  as-is (no rebuild needed) with the current worktree's `src/`/`poc/`
  bind-mounted read-only over its `/app` (its dependencies live in
  `/opt/venv`, confirmed separate from `/app` by reading
  `docker/Dockerfile`, so the bind mount does not shadow any installed
  package).

## Real containers created (all `kronos-poc-*`, all torn down after this run)

- `kronos-poc-wazuh-net` -- dedicated bridge network, not the shared dev
  stack's `docker_default` and not `kronos-internal` (which does not exist
  on this host -- the shared dev stack never created it).
- `kronos-poc-wazuh-manager` -- the real Wazuh manager.
- `kronos-poc-wazuh-receiver` -- the real KronOS FastAPI app + `WazuhPushSource`.

No container outside this PoC's own three was touched, restarted, or
`down`'d.

## Real mechanism confirmed (corrects the roadmap's own SS0 summary slightly)

The roadmap's SS0 research describes the mechanism as "hook_url/api_key/
alert_format json" as if any `hook_url` gets auto-POSTed to. Reading
`wazuh-integratord`'s own real, bundled scripts inside the running
`4.14.7` container (`/var/ossec/integrations/{slack,pagerduty,shuffle}.py`)
shows this is only true for Wazuh's five built-in vendor names
(slack/pagerduty/shuffle/virustotal/maltiverse), each of which ships its
own Python script that already knows what to do with those three values.
A `custom-*` name (required for any non-built-in target, confirmed via
`documentation.wazuh.com`) requires supplying that script yourself --
`wazuh-integratord` execs `/var/ossec/integrations/<name>` with argv
`[alert_file_path, api_key, hook_url, options_file, debug_flag]` (argv
indices confirmed from `slack.py`'s own `WEBHOOK_INDEX = 3` constant).
This PoC's `custom-kronos`/`custom-kronos.py` are exactly that missing
script -- a real shell wrapper (byte-for-byte structural copy of the
pattern used by every bundled script) plus a real Python script that reads
the alert file, validates it is JSON, and POSTs it verbatim to `hook_url`
with header `X-KronOS-Source-Key: <api_key>` (the exact header
`StaticApiKeyInboundAuthenticator` expects).

## Real `<integration>` block used (captured from the running container's own `ossec.conf`)

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>

<integration>
  <name>custom-kronos</name>
  <hook_url>http://kronos-poc-wazuh-receiver:8000/api/integrations/push/wazuh</hook_url>
  <api_key>kronos-poc-wazuh-demo-key</api_key>
  <alert_format>json</alert_format>
</integration>
```

## How the real alert was triggered

A real, safe, local action: appended a realistic `sshd` failed-password
syslog line to `/var/log/auth.log` (monitored by the `<localfile>` block
above), which the manager's own real, default, unmodified ruleset decodes
via its bundled `sshd` decoder and matches against real rule `5710`
("sshd: Attempt to login using a non-existent user", real MITRE ATT&CK
mapping T1110.001/T1021.004 attached by Wazuh itself) -- exactly the kind
of default-ruleset demo alert the roadmap's own brief suggested.

## How to reproduce

```bash
docker network create kronos-poc-wazuh-net

docker run -d --name kronos-poc-wazuh-manager --network kronos-poc-wazuh-net \
  wazuh/wazuh-manager:4.14.7
# wait ~20s for full boot, then:
docker cp <this-dir>/custom-kronos    kronos-poc-wazuh-manager:/var/ossec/integrations/custom-kronos
docker cp <this-dir>/custom-kronos.py kronos-poc-wazuh-manager:/var/ossec/integrations/custom-kronos.py
docker exec -u root kronos-poc-wazuh-manager sh -c \
  "chown root:wazuh /var/ossec/integrations/custom-kronos* && chmod 750 /var/ossec/integrations/custom-kronos*"
# append the <localfile>+<integration> block (see above) into ossec.conf, then:
docker exec -u root kronos-poc-wazuh-manager sh -c "touch /var/log/auth.log"
docker exec -u root kronos-poc-wazuh-manager /var/ossec/bin/wazuh-control restart

docker run -d --name kronos-poc-wazuh-receiver --network kronos-poc-wazuh-net \
  -v <repo-root>:/app:ro --entrypoint python3 \
  kronos-backend:dev /app/poc/integration_source_wazuh/run_poc_receiver.py 120

TS=$(date "+%b %e %H:%M:%S")
docker exec -u root kronos-poc-wazuh-manager sh -c \
  "echo '$TS 4b29f98ecc3d sshd[54321]: Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2' >> /var/log/auth.log"

docker logs -f kronos-poc-wazuh-receiver   # observe the real push land
```

## What `output.txt` actually captures (real, not reconstructed from memory)

1. Docker Hub / GitHub Releases API output proving `5.1.0` does not exist.
2. The real `5.0.0-beta4` container's own `find`/`cat` output proving
   `wazuh-integratord` and `ossec.conf` no longer exist in that line.
3. The real `4.14.7` boot log (clean, no errors, `wazuh-integratord`
   started, "Remote integrations not configured. Clean exit." *before*
   configuration).
4. The real `ossec.conf` `<integration>`/`<localfile>` block as read back
   from the running container.
5. The real triggered `sshd` alert as captured directly from the
   manager's own `logs/alerts/alerts.json`.
6. The real `wazuh-integratord`/`integrations.log` output showing: (a) two
   real connection-refused failures before the receiver was up (proves
   integratord really tried, on its own schedule, not on a mocked
   trigger), (b) two real `status=202` successes after the receiver came
   up, with real KronOS response bodies.
7. The real receiver-side stdout: two real inbound HTTP calls logged with
   full raw bodies, real `WazuhPushSource` validation passing, real
   `IntegrationSourceIngestService` outcomes (`accepted=True,
   duplicate=False`), real produced stream entries (`message_id=1-0`/
   `2-0`), and two real `AuditEvent`s of type
   `integration_source.push_ingested`.

## Honesty notes / what was NOT verified here

- **Only PUSH, never POLL** -- Wazuh's own real mechanism is push-shaped
  (`wazuh-integratord`), so `IntegrationDeliveryMode.POLL` was never
  exercised by this connector; that shape is already proven generically by
  Q1's own `GenericPollSource` PoC.
- **In-memory stream/dedup/audit doubles inside the receiver**, not real
  Redis/Postgres -- identical, already-accepted PoC-tier bar
  `poc/integration_source_foundation/run_poc_push.py` established (those
  real backends are independently verified in `poc/stream_ingest_redis/`
  and their own repository tests; re-proving them here would test Redis,
  not this connector).
- **No dev/prod-stage wiring** (SS3) -- no `docker-compose.dev.yml`/
  `prod.yml` service entry for a real customer's Wazuh manager, no real
  `StaticApiKeyProvisioning` wired into `startup.py`. Follow-up, matching
  Q1's own identical honesty note.
- **Only one alert shape (`sshd`/rule 5710) forwarded live end-to-end.**
  `WazuhAlertNormalizer` (the ECS-mapping half, run later by
  `StreamNormalizationService` once a batch is sealed -- not exercised by
  this PoC, which only proves fetch+produce, per
  `src/application/integration_source.py`'s own "why fetch is separate
  from mapping" design) was additionally verified against a second, real,
  structurally different captured alert (an SCA summary with no
  `full_log`/`data.srcuser`/`data.srcip` at all) in the real unit tests
  (`tests/unit/application/test_stream_source_registry.py`), not in this
  live PoC.
- **The `docker/wazuh/docker-compose.wazuh.yml` fix itself was not made**
  here -- flagged above, left for the orchestrator to route to the right
  owner (out of a source-connector module's own scope per CLAUDE.md SS G.4's
  "report, don't silently fix outside scope" idiom applied to
  infra config instead of application code).
