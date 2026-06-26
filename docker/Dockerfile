# syntax=docker/dockerfile:1
# Build stage — install runtime dependencies into a self-contained venv
FROM python:3.11-slim AS builder

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

# Runtime stage — minimal image
FROM python:3.11-slim

WORKDIR /app

# Non-root user for security
RUN useradd -r -m -d /home/kronos kronos

# Copy the venv (owned by the runtime user) and the application source
COPY --from=builder --chown=kronos:kronos /opt/venv /opt/venv
COPY --chown=kronos:kronos src/ ./src/
COPY --chown=kronos:kronos kronos_attest/ ./kronos_attest/
COPY --chown=kronos:kronos pyproject.toml .

ENV PATH=/opt/venv/bin:$PATH
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

USER kronos

EXPOSE 8000

# NOTE: step-up tickets and the JWKS cache are per-process (audit M-4). Running
# multiple workers/pods requires a shared store; until then run a single worker
# and scale via additional replicas behind the load balancer only once step-up
# state is externalised.
CMD ["uvicorn", "src.external.fastapi_app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
