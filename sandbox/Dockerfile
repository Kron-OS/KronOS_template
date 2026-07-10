# syntax=docker/dockerfile:1
#
# KronOS sandbox image — a hardened, self-contained box to *exercise the whole
# pipeline* (parsers, the real Plaso heavy path, the test suite, lint/type) and
# to be attached to from outside via SSH / the Claude Code CLI.
#
# It is deliberately NOT the production image. Production runs Chainguard/Wolfi
# distroless workers (docker/Dockerfile*, no shell, no sshd). This box trades
# that minimalism for interactive ergonomics, and compensates with strong
# *runtime* isolation configured in docker-compose.yml (non-root workload,
# dropped caps, no-new-privileges, and an egress firewall that blocks the local
# network so a compromise can't pivot into your LAN).
#
# Build context is the repo root so third-party deps can be installed from
# pyproject.toml (see docker-compose.yml: context is "..").

FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# --- system packages -------------------------------------------------------
#  iptables/iproute2 : the start-up egress firewall (block LAN).
#  gosu              : drop privileges from the root entrypoint to 'sandbox'.
#  openssh-server    : external access (key-only).
#  build-essential + python3-dev + libffi-dev : build any C extensions Plaso
#                      or evtx need if a wheel is unavailable.
#  nodejs/npm        : the Claude Code CLI.
#  git/ripgrep/jq/sqlite3/curl/less : day-to-day ergonomics inside the box.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git ripgrep jq sqlite3 less nano procps \
        iptables iproute2 gosu tini \
        openssh-server \
        build-essential python3-dev libffi-dev \
        # libyal / Plaso build deps: on arm64 most libyal wheels (libfsntfs,
        # libfsext, libvhdi, libmodi, libfsfat, …) don't exist and pip compiles
        # them from source. Their ./configure needs pkg-config (build-essential
        # doesn't provide it) plus zlib/openssl headers, else the build fails
        # with "configure: error: pkg-config not found".
        pkg-config zlib1g-dev libssl-dev \
        nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# --- Claude Code CLI -------------------------------------------------------
RUN npm install -g @anthropic-ai/claude-code && npm cache clean --force

# --- unprivileged workload user -------------------------------------------
ARG SANDBOX_UID=1000
ARG SANDBOX_GID=1000
RUN groupadd -g "${SANDBOX_GID}" sandbox \
    && useradd -m -u "${SANDBOX_UID}" -g sandbox -s /bin/bash sandbox

# --- Python toolchain venv (owned by the sandbox user) --------------------
# Third-party deps (project runtime + dev tooling + the full Plaso heavy path)
# are baked at build time so the box works even with the runtime egress
# firewall on. The live repo is bind-mounted at /home/sandbox/kronos at run
# time; run tests from there with the venv already on PATH.
COPY pyproject.toml /tmp/build/pyproject.toml
COPY src /tmp/build/src
COPY kronos_attest /tmp/build/kronos_attest
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install "/tmp/build[dev]" \
    # Plaso — pinned to the same release the production worker image uses
    # (docker/Dockerfile.plaso-worker) so the heavy path behaves identically.
    && /opt/venv/bin/pip install plaso==20260512 \
    && rm -rf /tmp/build \
    && chown -R sandbox:sandbox /opt/venv
ENV PATH=/opt/venv/bin:$PATH

# --- sshd hardening --------------------------------------------------------
# Key-only, no root login, single allowed user. Host keys are generated at
# first start by the entrypoint (kept out of the image).
RUN mkdir -p /run/sshd \
    && { \
        echo 'PermitRootLogin no'; \
        echo 'PasswordAuthentication no'; \
        echo 'ChallengeResponseAuthentication no'; \
        echo 'KbdInteractiveAuthentication no'; \
        echo 'PubkeyAuthentication yes'; \
        echo 'AllowUsers sandbox'; \
        echo 'X11Forwarding no'; \
        echo 'AllowTcpForwarding yes'; \
        echo 'PermitTunnel no'; \
        echo 'ClientAliveInterval 120'; \
    } > /etc/ssh/sshd_config.d/kronos-sandbox.conf

COPY sandbox/firewall.sh /usr/local/bin/firewall.sh
COPY sandbox/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/firewall.sh /usr/local/bin/entrypoint.sh

EXPOSE 22

# tini reaps zombies; the entrypoint sets up the firewall + sshd as root, then
# all interactive logins land as the unprivileged 'sandbox' user.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
