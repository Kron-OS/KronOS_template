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
| Reaching your LAN / host / other containers | Start-up **egress firewall** drops all traffic to RFC1918 + link-local + CGNAT + multicast. Enforced by root before any workload runs; the workload is non-root and can't undo it. |
| Seeing your other repos / files | Bind-mounts **only this repository** (`..`) — nothing else on your machine is visible. |
| Privilege escalation | `cap_drop: ALL` (only what root needs to set the firewall + run sshd is added back), `no-new-privileges: true`, non-root login user. |
| Runaway resource use | `pids_limit`, `mem_limit`, `tmpfs` scratch. |
| Inbound exposure | SSH is key-only, `PermitRootLogin no`, single `AllowUsers sandbox`, and the port is bound to host **loopback** by default. |

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
ssh -p 2222 sandbox@127.0.0.1
```

**Without SSH** (no key configured, or you prefer exec):
```bash
docker exec -it -u sandbox kronos-sandbox bash
```

**Claude Code** — the `claude` CLI is preinstalled. Either SSH in and run
`claude` in `~/kronos`, or point a Claude Code remote/SSH environment at
`sandbox@127.0.0.1:2222`. To reach the box from another machine, prefer an SSH
tunnel (`ssh -L 2222:127.0.0.1:2222 <docker-host>`) rather than exposing the
port on your LAN.

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
non-root, and only sees this repo.

- **All actions permitted without asking.** The entrypoint seeds
  `~/.claude/settings.json` with `{"permissions": {"defaultMode":
  "bypassPermissions"}}` inside the container's own home volume — so `claude`
  never prompts for edits/commands here, and this setting **does not touch your
  host's Claude Code sessions** on the same repo. (Written only if absent, so
  your own edits persist. To restore prompting, set `defaultMode` to `default`
  or delete the file.)

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
- **Stronger runtime isolation**: install [Sysbox](https://github.com/nestybox/sysbox)
  on the host and uncomment `runtime: sysbox-runc`. This user-namespaces the
  container and lets it safely run nested Docker/systemd/Firecracker (e.g. the
  real Firecracker Plaso sandbox).
- **Expose SSH beyond loopback**: change `127.0.0.1:2222:22` to `2222:22`
  (understand the exposure first) — or, better, keep loopback and tunnel.
- **Disable the firewall** (debugging only): `SANDBOX_FIREWALL=0` in `.env`.

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | The sandbox image: Python venv (project + dev deps + Plaso), Node + Claude Code CLI, sshd, firewall tooling. |
| `docker-compose.yml` | Runs it with the hardening + isolated network + single repo mount. |
| `entrypoint.sh` | Root: apply firewall, provision sshd/keys, then `exec sshd` (logins are non-root). |
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
- `no-new-privileges` + sshd privilege-separation are compatible (sshd starts
  as root and *drops* to the login user; that's not a privilege *gain*). If
  your host kernel/seccomp is unusually strict and sshd fails to start, run the
  box via `docker exec` while you adjust `cap_add`.
