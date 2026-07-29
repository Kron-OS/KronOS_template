#!/usr/bin/env bash
#
# Applies firewall.sh, gated by the SANDBOX_FIREWALL toggle. Run by
# kronos-firewall.service, which ssh.service and docker.service both
# `Requires=` — so if this fails (set -e), neither SSH nor the nested Docker
# daemon comes up, refusing to start unprotected.

set -euo pipefail

if [ "${SANDBOX_FIREWALL:-1}" = "1" ]; then
    /usr/local/bin/firewall.sh
else
    echo "[kronos-firewall] WARNING: SANDBOX_FIREWALL=0 — local network is NOT blocked" >&2
fi
