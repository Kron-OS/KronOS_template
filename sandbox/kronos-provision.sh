#!/usr/bin/env bash
#
# One-time-per-boot provisioning run by kronos-provision.service, before
# ssh.service starts: SSH host keys, authorized_keys, a friendly shell, and
# Claude Code's prompt-free settings.

set -euo pipefail

log() { echo "[kronos-provision] $*" >&2; }

HOME_DIR=/root
REPO_DIR="${HOME_DIR}/kronos"

# --- SSH host keys ----------------------------------------------------------
mkdir -p /run/sshd
ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || ssh-keygen -A >/dev/null

# --- authorized_keys (home may be an empty named volume on first start) -----
install -d -m 700 "${HOME_DIR}/.ssh"
AUTH_KEYS="${HOME_DIR}/.ssh/authorized_keys"
if [ -n "${SANDBOX_SSH_PUBKEY:-}" ]; then
    printf '%s\n' "${SANDBOX_SSH_PUBKEY}" > "${AUTH_KEYS}"
    log "authorized_keys set from SANDBOX_SSH_PUBKEY"
elif [ -f "${REPO_DIR}/sandbox/authorized_keys" ]; then
    cp "${REPO_DIR}/sandbox/authorized_keys" "${AUTH_KEYS}"
    log "authorized_keys set from sandbox/authorized_keys"
else
    log "WARNING: no SSH public key provided — SSH login will be impossible."
    log "         Set SANDBOX_SSH_PUBKEY in sandbox/.env, or use: docker exec -it kronos-sandbox bash"
fi
chmod 600 "${AUTH_KEYS}" 2>/dev/null || true

# --- Seed a friendly shell (home volume starts empty) -----------------------
# The banner is wrapped in an interactive-shell guard. This is load-bearing,
# not cosmetic: bash sources ~/.bashrc even NON-interactively when sshd runs a
# remote *command* (its stdin is a socket), so any stdout emitted here lands on
# that command channel. Remote-dev clients — Claude Code's SSH remote and the
# SFTP bootstrap it opens, VS Code Remote-SSH, etc. — need that channel's
# stdout pristine; a stray banner byte corrupts their handshake. The classic
# symptom is "plain `ssh` works but the tool fails to open an SFTP session".
# PATH/cd/alias stay unguarded (they emit nothing) so non-interactive commands
# still find the venv. Re-seeded every boot via BEGIN/END markers so a home
# volume created before this fix is healed on the next restart.
MARK_BEGIN="# --- kronos-sandbox (managed; do not edit inside) ---"
MARK_END="# --- end kronos-sandbox ---"
BASHRC="${HOME_DIR}/.bashrc"
[ -f "${BASHRC}" ] && sed -i "\|${MARK_BEGIN}|,\|${MARK_END}|d" "${BASHRC}"
cat >> "${BASHRC}" <<BASHRC_BLOCK
${MARK_BEGIN}
export PATH=/opt/venv/bin:\$PATH
if [ -d "\$HOME/kronos" ]; then cd "\$HOME/kronos"; fi
alias t='python -m pytest tests/unit -q --no-cov'
if [[ \$- == *i* ]]; then
    echo "KronOS sandbox (root/Sysbox) — venv on PATH (python/pytest/ruff/black/mypy), Plaso installed."
    echo "  run tests:   python -m pytest tests/unit -q --no-cov"
    echo "  heavy path:  log2timeline.py --version ; psort.py --version"
    echo "  claude:      claude          (permissions bypassed in this box)"
    echo "  unattended:  claude-auto ..  (auto-resumes across Plan usage limits)"
fi
${MARK_END}
BASHRC_BLOCK

# --- Claude Code: permit all actions without prompting -----------------------
# This is a locked-down box — network-isolated (no LAN), Sysbox-isolated,
# only this repo mounted — so unattended, prompt-free operation is the whole
# point. Scoped to the container's own ~/.claude (a named volume), so it never
# affects Claude Code sessions on your host. Written only if absent.
install -d -m 700 "${HOME_DIR}/.claude"
CLAUDE_SETTINGS="${HOME_DIR}/.claude/settings.json"
if [ ! -f "${CLAUDE_SETTINGS}" ]; then
    cat > "${CLAUDE_SETTINGS}" <<'JSON'
{
  "permissions": {
    "defaultMode": "bypassPermissions"
  }
}
JSON
    log "seeded ~/.claude/settings.json with bypassPermissions (no prompts)"
fi
