# syntax=docker/dockerfile:1
# Build stage — install runtime dependencies into a self-contained venv.
# cgr.dev/chainguard/python:latest-dev is the Wolfi-based dev variant (has a
# shell, pip, and a package manager) — mirrors docker/plaso/Dockerfile, this
# project's reference pattern for Chainguard images (INFRA-005).
FROM cgr.dev/chainguard/python:latest-dev AS builder

# Chainguard images run as the built-in "nonroot" user by default — even the
# "-dev" variants — so /opt (and any other root-owned path) isn't writable
# without this. Safe here: this is a discarded builder stage in a
# multi-stage build: root privileges never reach the runtime image below,
# which still explicitly runs as USER nonroot.
USER root

WORKDIR /app
COPY pyproject.toml .
COPY src/ ./src/
COPY kronos_attest/ ./kronos_attest/

# Build into a venv at a world-readable path so the non-root runtime user can
# use it (installing with --user lands in /root/.local, which is mode 0700 and
# unreadable by an unprivileged user). Runtime deps only — no dev/test tooling.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir .

# Pre-create the log directory that docker-compose mounts the `kronos_app_logs`
# named volume onto (KRONOS_LOG_FILE=/var/log/kronos/{app,celery}.log). The
# runtime stage runs as the non-root "nonroot" user (uid 65532) but a fresh
# named volume is otherwise created root-owned, so opening the log file there
# fails with EACCES — which, because configure_logging() runs at
# src/external/celery_app.py *import* time, surfaces as celery's cryptic
# "module 'src.external' has no attribute 'celery_app'" rather than the real
# PermissionError. Docker seeds an empty named volume from the ownership of the
# image directory it mounts over, so creating this dir owned by nonroot here
# makes the volume writable by the app. The .keep file guarantees the dir is
# non-empty so the volume-seeding copy (and its ownership) always triggers.
RUN mkdir -p /var/log/kronos && touch /var/log/kronos/.keep

# Runtime stage — minimal image. cgr.dev/chainguard/python:latest is the
# non-dev, distroless-style variant: no shell, no package manager, so there is
# no `useradd` here — it ships only python3/libs plus a built-in "nonroot"
# user (uid/gid 65532), the same convention docker/plaso/Dockerfile already
# uses. Non-root COPY --chown + USER nonroot below replaces the old
# `useradd kronos` step (H-2/M-5 fixes from docs/SECURITY_AUDIT.md are
# preserved: self-contained venv, runtime-only deps, non-root execution).
FROM cgr.dev/chainguard/python:latest

WORKDIR /app

# Copy the venv (owned by the runtime user) and the application source
COPY --from=builder --chown=nonroot:nonroot /opt/venv /opt/venv
COPY --chown=nonroot:nonroot src/ ./src/
COPY --chown=nonroot:nonroot kronos_attest/ ./kronos_attest/
COPY --chown=nonroot:nonroot pyproject.toml .
# Alembic (Gap Audit P1-12 / Milestone V4): the `db-migrate` service in
# docker-compose.{dev,test,prod}.yml runs `alembic upgrade head` using THIS
# same built image (command override, no separate Dockerfile) -- see
# docs/DATABASE_MIGRATIONS.md. alembic.ini's own `script_location`/
# `prepend_sys_path` are relative to WORKDIR /app, matching every other
# path in this image.
COPY --chown=nonroot:nonroot alembic.ini .
COPY --chown=nonroot:nonroot migrations/ ./migrations/

# nonroot-owned log dir (see builder stage) so the mounted kronos_app_logs
# volume is writable by uid 65532. The runtime image has no shell, so this
# must be carried over from the builder rather than created with RUN mkdir.
COPY --from=builder --chown=nonroot:nonroot /var/log/kronos /var/log/kronos

ENV PATH=/opt/venv/bin:$PATH
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

USER nonroot

EXPOSE 8000

# cgr.dev/chainguard/python images bake in ENTRYPOINT ["/usr/bin/python"], so
# any CMD (or a docker-compose `command:` override — e.g. celery-worker /
# celery-beat / kronos-backend in docker-compose.dev.yml) is otherwise
# appended as ARGUMENTS to that python interpreter, i.e. it actually runs
# `python uvicorn src.external.fastapi_app:app ...`, and python tries to open
# "uvicorn" as a script path relative to WORKDIR /app — hence "can't open
# file '/app/uvicorn'" (same failure for "celery"). Clearing the entrypoint
# here restores normal exec-form CMD/command semantics for every service
# built from this image.
ENTRYPOINT []

# NOTE: step-up tickets and the JWKS cache are per-process (audit M-4). Running
# multiple workers/pods requires a shared store; until then run a single worker
# and scale via additional replicas behind the load balancer only once step-up
# state is externalised.
CMD ["uvicorn", "src.external.fastapi_app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
