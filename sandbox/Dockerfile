# syntax=docker/dockerfile:1
#
# KronOS sandbox image — a hardened, self-contained box to *exercise the whole
# pipeline* (parsers, the real Plaso heavy path, the test suite, lint/type) and
# to be attached to from outside via SSH / the Claude Code CLI.
#
# Runs as root inside the container, isolated by Sysbox runtime.
# Build context is the repo root so third-party deps can be installed from pyproject.toml.

FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# --- system packages -------------------------------------------------------
#  iptables/iproute2 : the start-up egress firewall (block LAN).
#  openssh-server, openssh-sftp-server : external access (key-only) + the
#                      sftp subsystem. Listed explicitly (not just pulled in
#                      transitively) since --no-install-recommends can drop it
#                      depending on how the base image's package graph is
#                      structured, which breaks SFTP-based clients (e.g. the
#                      Claude Code SSH remote) while plain interactive ssh
#                      still works fine.
#  build-essential + python3-dev + libffi-dev : build any C extensions Plaso
#                      or evtx need if a wheel is unavailable.
#  nodejs/npm        : the Claude Code CLI.
#  git/ripgrep/jq/sqlite3/curl/less : day-to-day ergonomics inside the box.
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus dbus-user-session \
        ca-certificates gpg curl git ripgrep jq sqlite3 less nano procps \
        iptables iproute2 \
        openssh-server openssh-sftp-server \
        build-essential python3-dev libffi-dev \
        pkg-config zlib1g-dev libssl-dev \
        nodejs npm \
    && rm -rf /var/lib/apt/lists/*


RUN systemctl mask \
        systemd-udevd.service systemd-udevd-kernel.socket systemd-udevd-control.socket \
        systemd-firstboot.service \
        systemd-random-seed.service \
        systemd-machine-id-commit.service \
        getty.target getty-static.service console-getty.service \
        systemd-remount-fs.service \
        sys-kernel-config.mount sys-kernel-debug.mount sys-kernel-tracing.mount


# --- Claude Code CLI -------------------------------------------------------
RUN npm install -g @anthropic-ai/claude-code && npm cache clean --force

# --- Python toolchain venv (owned by root) ---------------------------------
# Third-party deps (project runtime + dev tooling + the full Plaso heavy path)
# are baked at build time so the box works even with the runtime egress
# firewall on. The live repo is bind-mounted at /root/kronos at run time.
COPY pyproject.toml /tmp/build/pyproject.toml
COPY src /tmp/build/src
COPY kronos_attest /tmp/build/kronos_attest
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install "/tmp/build[dev]" \
    # Plaso — pinned to the same release the production worker image uses
    # (docker/Dockerfile.plaso-worker) so the heavy path behaves identically.
    && /opt/venv/bin/pip install plaso==20260512 \
    && rm -rf /tmp/build
ENV PATH=/opt/venv/bin:$PATH

# --- Docker (DinD via Sysbox) -----------------------------------------------
RUN curl -fsSL https://download.docker.com/linux/debian/gpg \
        | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/debian bookworm stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*
RUN systemctl enable docker


# --- sshd hardening --------------------------------------------------------
# Key-only, root login allowed (Sysbox isolates the host). Host keys are
# generated at first boot by kronos-provision.service (kept out of the image).
#
# SetEnv IS_SANDBOX=1 marks every SSH session as sandboxed so Claude Code's
# bypass-permissions mode works under root (it otherwise refuses to skip
# prompts as uid 0). It covers interactive shells AND the non-interactive
# command channel the Claude Code SSH remote uses.
RUN mkdir -p /run/sshd \
    && { \
        echo 'PermitRootLogin yes'; \
        echo 'PasswordAuthentication no'; \
        echo 'ChallengeResponseAuthentication no'; \
        echo 'KbdInteractiveAuthentication no'; \
        echo 'PubkeyAuthentication yes'; \
        echo 'AllowUsers root'; \
        echo 'X11Forwarding no'; \
        echo 'AllowTcpForwarding yes'; \
        echo 'PermitTunnel no'; \
        echo 'ClientAliveInterval 120'; \
        echo 'SetEnv IS_SANDBOX=1'; \
    } > /etc/ssh/sshd_config.d/kronos-sandbox.conf

# Same flag for non-SSH entry points: Docker injects image ENV into
# `docker exec`, so `claude` run that way is prompt-free under root too.
ENV IS_SANDBOX=1

COPY sandbox/firewall.sh /usr/local/bin/firewall.sh
COPY sandbox/kronos-capture-env.sh /usr/local/bin/kronos-capture-env.sh
COPY sandbox/kronos-firewall-guard.sh /usr/local/bin/kronos-firewall-guard.sh
COPY sandbox/kronos-provision.sh /usr/local/bin/kronos-provision.sh
COPY sandbox/claude-auto.sh /usr/local/bin/claude-auto
RUN chmod 0755 /usr/local/bin/firewall.sh /usr/local/bin/kronos-capture-env.sh \
        /usr/local/bin/kronos-firewall-guard.sh /usr/local/bin/kronos-provision.sh \
        /usr/local/bin/claude-auto

# --- systemd boot: firewall, provisioning, ssh, docker ----------------------
# Sysbox gives the container a real init system, so the box boots like a VM
# instead of a single hand-run script: systemd brings up kronos-boot (capture
# Docker/Compose env for units), kronos-firewall (egress firewall — a hard
# `Requires=` of both ssh.service and docker.service, so neither starts
# unprotected), kronos-provision (host keys / authorized_keys / shell /
# claude config), then ssh.service and docker.service themselves.
COPY sandbox/systemd/kronos-boot.service /etc/systemd/system/kronos-boot.service
COPY sandbox/systemd/kronos-firewall.service /etc/systemd/system/kronos-firewall.service
COPY sandbox/systemd/kronos-provision.service /etc/systemd/system/kronos-provision.service
COPY sandbox/systemd/ssh.service.d/kronos.conf /etc/systemd/system/ssh.service.d/kronos.conf
COPY sandbox/systemd/docker.service.d/kronos.conf /etc/systemd/system/docker.service.d/kronos.conf
RUN systemctl enable kronos-boot.service kronos-firewall.service kronos-provision.service ssh

EXPOSE 22

# systemd is PID 1 (Sysbox-provided isolation makes this safe); it reaps
# zombies itself, so no tini wrapper is needed. `docker stop` sends SIGTERM
# by default, which systemd-as-PID1 does not treat as a clean shutdown
# request — SIGRTMIN+3 is systemd's "start default poweroff/halt target"
# signal.
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/sbin/init"]