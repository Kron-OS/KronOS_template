FROM cgr.dev/chainguard/python:latest-dev AS build

# Install Plaso and its dependencies into a virtual environment.
RUN python -m venv /opt/plaso-venv
ENV PATH="/opt/plaso-venv/bin:${PATH}"
RUN pip install --no-cache-dir plaso==20240101 || pip install --no-cache-dir plaso

FROM cgr.dev/chainguard/python:latest

LABEL org.opencontainers.image.title="KronOS Plaso Worker"
LABEL org.opencontainers.image.description="Heavy forensic parser — Plaso in Firecracker-compatible container"

COPY --from=build /opt/plaso-venv /opt/plaso-venv
ENV PATH="/opt/plaso-venv/bin:${PATH}"

COPY kronos-plaso-worker.py /app/kronos-plaso-worker.py

WORKDIR /app
USER nonroot

ENTRYPOINT ["python", "/app/kronos-plaso-worker.py"]
