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

- These artifacts were authored but **not built or run** in the environment
  that generated them (image building is out of scope there). Expect to iterate
  on the first `--build` — most likely on Plaso's transitive apt/pip deps for
  your host arch. If a Plaso wheel needs a system lib, add it to the
  `apt-get install` line in the `Dockerfile`.
- `no-new-privileges` + sshd privilege-separation are compatible (sshd starts
  as root and *drops* to the login user; that's not a privilege *gain*). If
  your host kernel/seccomp is unusually strict and sshd fails to start, run the
  box via `docker exec` while you adjust `cap_add`.
