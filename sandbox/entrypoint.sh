#!/usr/bin/env bash
#
# Sandbox entrypoint. Runs as root only long enough to (1) install the egress
# firewall and (2) provision SSH, then execs sshd. Every interactive login
# lands as the unprivileged 'sandbox' user, which has no CAP_NET_ADMIN and so
# cannot undo the firewall.

set -euo pipefail

log() { echo "[sandbox-entrypoint] $*" >&2; }

HOME_DIR=/home/sandbox
REPO_DIR="${HOME_DIR}/kronos"

# --- 1) Egress firewall (block the local network) --------------------------
if [ "${SANDBOX_FIREWALL:-1}" = "1" ]; then
    if /usr/local/bin/firewall.sh; then
        log "egress firewall active"
    else
        log "FATAL: firewall failed to apply; refusing to start unprotected"
        exit 1
    fi
else
    log "WARNING: SANDBOX_FIREWALL=0 — local network is NOT blocked"
fi

# --- 2) SSH host keys ------------------------------------------------------
mkdir -p /run/sshd
ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || ssh-keygen -A >/dev/null

# --- 3) authorized_keys (home may be an empty named volume on first start) -
install -d -o sandbox -g sandbox -m 700 "${HOME_DIR}/.ssh"
AUTH_KEYS="${HOME_DIR}/.ssh/authorized_keys"
if [ -n "${SANDBOX_SSH_PUBKEY:-}" ]; then
    printf '%s\n' "${SANDBOX_SSH_PUBKEY}" > "${AUTH_KEYS}"
    log "authorized_keys set from SANDBOX_SSH_PUBKEY"
elif [ -f "${REPO_DIR}/sandbox/authorized_keys" ]; then
    cp "${REPO_DIR}/sandbox/authorized_keys" "${AUTH_KEYS}"
    log "authorized_keys set from sandbox/authorized_keys"
else
    log "WARNING: no SSH public key provided — SSH login will be impossible."
    log "         Set SANDBOX_SSH_PUBKEY in sandbox/.env, or use: docker exec -it -u sandbox kronos-sandbox bash"
fi
chown sandbox:sandbox "${AUTH_KEYS}" 2>/dev/null || true
chmod 600 "${AUTH_KEYS}" 2>/dev/null || true

# --- 4) Seed a friendly shell (home volume starts empty) -------------------
if [ ! -f "${HOME_DIR}/.bashrc" ] || ! grep -q "kronos-sandbox" "${HOME_DIR}/.bashrc" 2>/dev/null; then
    cat >> "${HOME_DIR}/.bashrc" <<'BASHRC'
# --- kronos-sandbox ---
export PATH=/opt/venv/bin:$PATH
if [ -d "$HOME/kronos" ]; then cd "$HOME/kronos"; fi
alias t='python -m pytest tests/unit -q --no-cov'
echo "KronOS sandbox — venv on PATH (python/pytest/ruff/black/mypy), Plaso installed."
echo "  run tests:   python -m pytest tests/unit -q --no-cov"
echo "  heavy path:  log2timeline.py --version ; psort.py --version"
BASHRC
    chown sandbox:sandbox "${HOME_DIR}/.bashrc"
fi

# --- 5) Drop root: exec sshd (only root process; logins are 'sandbox') -----
log "starting sshd (container :22 -> host :2222 by default)"
exec /usr/sbin/sshd -D -e
