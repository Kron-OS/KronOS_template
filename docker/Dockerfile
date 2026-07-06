# syntax=docker/dockerfile:1
# Build stage — install runtime dependencies into a self-contained venv.
# cgr.dev/chainguard/python:latest-dev is the Wolfi-based dev variant (has a
# shell, pip, and a package manager) — mirrors docker/plaso/Dockerfile, this
# project's reference pattern for Chainguard images (INFRA-005).
FROM cgr.dev/chainguard/python:latest-dev AS builder

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

ENV PATH=/opt/venv/bin:$PATH
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

USER nonroot

EXPOSE 8000

# NOTE: step-up tickets and the JWKS cache are per-process (audit M-4). Running
# multiple workers/pods requires a shared store; until then run a single worker
# and scale via additional replicas behind the load balancer only once step-up
# state is externalised.
CMD ["uvicorn", "src.external.fastapi_app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
