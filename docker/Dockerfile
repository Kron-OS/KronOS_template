# syntax=docker/dockerfile:1
# Build stage — install dependencies
FROM python:3.11-slim AS builder

WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir --user -e ".[dev]" 2>/dev/null || pip install --no-cache-dir --user -e .

# Runtime stage — minimal image
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local
COPY src/ ./src/
COPY pyproject.toml .

ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Non-root user for security
RUN useradd -r -s /bin/false kronos
USER kronos

EXPOSE 8000
CMD ["uvicorn", "src.external.fastapi_app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
