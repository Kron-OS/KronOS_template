# KronOS Sandbox

A hardened, network-isolated container for **exercising the whole ingestion
pipeline end-to-end** — the FAST parsers, the real **Plaso** heavy path
(`log2timeline` / `psort`), the full test suite, and lint/type — and for
**attaching to from outside** via SSH or the Claude Code CLI.

It is intentionally separate from the production images (`docker/Dockerfile*`),
which are distroless Chainguard/Wolfi workers with no shell. This box trades
that minimalism for interactive ergonomics and compensates with strong
**runtime** isolation.

---

## Why it's safe to run untrusted evidence here

The sandbox parses attacker-controlled files, so it is treated as
potentially-compromised and boxed in on every axis:

| Concern | Control |
|---|---|
| Reaching your LAN / host / other containers | Start-up **egress firewall** (`kronos-firewall.service`) drops all traffic to RFC1918 + link-local + CGNAT + multicast. `ssh.service` and `docker.service` both `Requires=` it, so neither comes up until it has applied. |
| Seeing your other repos / files | Bind-mounts **only this repository** (`..`) — nothing else on your machine is visible. |
| Editing its own isolation config | The `sandbox/` directory is mounted **read-only** — the workload can read its own config (compose, Dockerfile, firewall, units) but can't rewrite the definition of its own sandbox from inside. |
| Privilege escalation | Sysbox runtime (user-namespaced root), `no-new-privileges` semantics from Sysbox isolation. |
| Runaway resource use | `pids_limit`, `mem_limit`, `tmpfs` scratch. |
| Inbound exposure | SSH is key-only, `PasswordAuthentication no`, and the port is bound to host **loopback** by default. |

**Internet is still allowed** (for `pip`/`plaso`/`apt`) — only the *local
network* is blocked, which is the stated threat. Blocking RFC1918 does not
break internet access because internet packets carry public destination IPs
and are NAT'd out normally; see `firewall.sh` for the reasoning. For a full
air-gap, flip one switch (below).

---

## Setup

```bash
cd <repo root>
cp sandbox/.env.example sandbox/.env
# paste your SSH public key (one line) into SANDBOX_SSH_PUBKEY in sandbox/.env
#   e.g.:  echo "SANDBOX_SSH_PUBKEY=$(cat ~/.ssh/id_ed25519.pub)" >> sandbox/.env

docker compose -f sandbox/docker-compose.yml up -d --build
```

First build is slow (Plaso + toolchain). Subsequent starts are instant.

## Connect

**SSH** (default; port bound to host loopback):
```bash
ssh -p 50923 root@127.0.0.1
```

**Without SSH** (no key configured, or you prefer exec):
```bash
docker exec -it kronos-sandbox bash
```

**Claude Code** — the `claude` CLI is preinstalled. Either SSH in and run
`claude` in `~/kronos`, or point a Claude Code remote/SSH environment at
`root@127.0.0.1:50923`. To reach the box from another machine, prefer an SSH
tunnel (`ssh -L 50923:127.0.0.1:50923 <docker-host>`) rather than exposing the
port on your LAN.

> **Host keys are persisted** on the dedicated `sandbox_ssh` volume
> (`~/.ssh/hostkeys`) so the fingerprint is stable across `up --build`
> rebuilds — it even survives wiping the home volume. Clients that pin host
> keys (notably Claude Code's SSH remote, which reports a mismatch as
> `Host denied (verification failed)` and offers no re-accept prompt) then keep
> working after the first accept. If you ever *do* need a fresh identity, run
> `docker volume rm kronos-sandbox_sandbox_ssh` (or `rm ~/.ssh/hostkeys/*`) and
> restart, then clear the stale entry on the client
> (`ssh-keygen -R "[127.0.0.1]:50923"`).

## Exercise the pipeline

Inside the box (you start in `~/kronos`, venv already on `PATH`):

```bash
python -m pytest tests/unit -q --no-cov         # full unit suite (Plaso installed)
python -m pytest tests/unit/test_pipeline_end_to_end.py -q --no-cov
ruff check src tests && black --check src tests && mypy src

# Real Plaso heavy path (now actually runs here):
log2timeline.py --version
psort.py --version
python docker/plaso/kronos-plaso-worker.py \
    --evidence-path tests/fixtures/samples/real/CMD.EXE-087B4001.pf \
    --evidence-id e --case-id c --org-id o --org-alias acme --sha256 x
```

---

## Claude Code in the box

The `claude` CLI is preinstalled and configured for **unattended, prompt-free**
operation, which is safe here precisely because the box is network-isolated,
Sysbox-isolated, and only sees this repo.

- **All actions permitted without asking.** `kronos-provision.service` seeds
  `~/.claude/settings.json` with `{"permissions": {"defaultMode":
  "bypassPermissions"}}` inside the container's own home volume — so `claude`
  never prompts for edits/commands here, and this setting **does not touch your
  host's Claude Code sessions** on the same repo. (Written only if absent, so
  your own edits persist. To restore prompting, set `defaultMode` to `default`
  or delete the file.) The image also exports **`IS_SANDBOX=1`** (via sshd
  `SetEnv` for SSH sessions and image `ENV` for `docker exec`); without it
  Claude Code refuses bypass-permissions mode under `root` and would prompt
  anyway. This is why the box runs prompt-free even though login is root.

- **Auto-resume across Plan usage limits** — `claude-auto`:

  ```bash
  claude-auto                     # interactive; rides through usage-limit windows
  claude-auto -p "run the tests"  # headless task; same
  ```

  It runs `claude`, and when the plan's usage window is exhausted it waits until
  the window resets (parsed from Claude's message when possible, otherwise a
  periodic retry) and then **`--continue`s the same conversation** so nothing is
  lost. A non-limit exit is passed straight through — it doesn't mask real
  crashes. Tunables (env): `CLAUDE_AUTO_FALLBACK_SLEEP` (default 1200s),
  `CLAUDE_AUTO_MAX_RETRIES` (0 = unlimited), `CLAUDE_AUTO_BUFFER`, `CLAUDE_BYPASS`
  (1 = also pass `--dangerously-skip-permissions`).

  > For reliable unattended runs use a **headless** invocation (`-p "..."`):
  > Claude exits when it hits the limit, which is what lets the supervisor
  > detect it, wait, and resume. Pair it with `nohup`/`tmux` and it will keep a
  > long task moving across multiple usage windows on its own.

## Toggles

- **Full air-gap** (no internet either): set `internal: true` on `sandbox_net`
  in `docker-compose.yml`. Published ports stop working on internal networks,
  so connect via `docker exec` instead of SSH.
- **Runtime isolation**: requires [Sysbox](https://github.com/nestybox/sysbox)
  on the host (`runtime: sysbox-runc` is already set in `docker-compose.yml`).
  This user-namespaces the container and gives it a real init system, so it
  can safely run systemd, nested Docker, and Firecracker (e.g. the real
  Firecracker Plaso sandbox) as first-class managed services.
- **Expose SSH beyond loopback**: change `50923:22` to a host-wide bind
  (understand the exposure first) — or, better, keep loopback and tunnel.
- **Disable the firewall** (debugging only): `SANDBOX_FIREWALL=0` in `.env`.

## Boot sequence (systemd)

Sysbox lets the container run a real init, so the box boots like a small VM
rather than a single hand-run script — `ENTRYPOINT ["/sbin/init"]` starts
systemd, which brings units up in this order:

```
kronos-boot.service       (capture Compose env vars for later units)
  └─► kronos-firewall.service   (apply the egress firewall; Requires'd by:)
        ├─► ssh.service         (after kronos-provision.service too)
        └─► docker.service      (nested Docker daemon)
kronos-provision.service  (SSH host keys, authorized_keys, shell, claude config)
```

`ssh.service` and `docker.service` each carry a `Requires=kronos-firewall.service`
drop-in (`systemd/ssh.service.d/`, `systemd/docker.service.d/`), so if the
firewall unit fails, neither comes up — the box refuses to start unprotected.

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | The sandbox image: Python venv (project + dev deps + Plaso), Node + Claude Code CLI, sshd, Docker, systemd units. |
| `docker-compose.yml` | Runs it with the hardening + isolated network + single repo mount (`sandbox/` mounted read-only inside the box — see above). |
| `systemd/` | Unit files + drop-ins wiring the firewall/provisioning/ssh/docker boot sequence (see below). |
| `kronos-capture-env.sh` | Copies `SANDBOX_*` vars from `/proc/1/environ` so systemd units can read them. |
| `kronos-firewall-guard.sh` | Applies (or, if `SANDBOX_FIREWALL=0`, skips with a warning) `firewall.sh`. |
| `kronos-provision.sh` | SSH host keys, `authorized_keys`, shell seed, Claude Code settings — run before `ssh.service`. |
| `firewall.sh` | iptables rules blocking the local network. |
| `.env.example` | Your SSH pubkey + firewall toggle (copy to `.env`). |

## Notes / caveats

- **First build is slow, especially on arm64/Apple Silicon.** Plaso pulls ~20
  libyal C libraries (libfsntfs, libfsext, libvhdi, …). On x86_64 most arrive
  as prebuilt wheels; on **arm64 many have no wheel and are compiled from
  source**, which is why the image ships the libyal build deps
  (`pkg-config zlib1g-dev libssl-dev` alongside `build-essential`). Budget
  10–20 min for the first `docker compose build`; it's cached afterwards. If a
  future Plaso release adds a lib that needs another system header, add it to
  the `apt-get install` line in the `Dockerfile` (the build error names the
  missing `configure` dependency).
- Requires the [Sysbox](https://github.com/nestybox/sysbox) container runtime
  on the host (`runtime: sysbox-runc` in `docker-compose.yml`) — plain
  `runc`/`containerd` cannot run systemd-as-PID1 with a nested Docker daemon
  safely. If `docker compose up` fails with an unknown-runtime error, install
  Sysbox first.
