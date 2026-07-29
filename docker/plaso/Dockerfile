FROM cgr.dev/chainguard/python:latest-dev AS build

# Chainguard images run as the built-in "nonroot" user by default — even the
# "-dev" variants — so /opt isn't writable without this. Safe here: this is
# a discarded builder stage in a multi-stage build; the runtime stage below
# still runs as USER nonroot.
USER root

# Install Plaso and its dependencies into a virtual environment.
RUN python -m venv /opt/plaso-venv
ENV PATH="/opt/plaso-venv/bin:${PATH}"
RUN pip install --no-cache-dir plaso==20260512

FROM cgr.dev/chainguard/python:latest

LABEL org.opencontainers.image.title="KronOS Plaso Worker"
LABEL org.opencontainers.image.description="Heavy forensic parser — Plaso in Firecracker-compatible container"

COPY --from=build --chown=nonroot:nonroot /opt/plaso-venv /opt/plaso-venv
ENV PATH="/opt/plaso-venv/bin:${PATH}"

COPY --chown=nonroot:nonroot kronos-plaso-worker.py /app/kronos-plaso-worker.py

WORKDIR /app
USER nonroot

ENTRYPOINT ["python", "/app/kronos-plaso-worker.py"]
