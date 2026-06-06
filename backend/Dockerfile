# ===========================================================================
# Backend Dockerfile — AgentOps Security Mesh FastAPI Application
# Multi-stage build for a lean production image.
# ===========================================================================

# Stage 1: Builder — install dependencies into a virtual environment
FROM python:3.11-slim AS builder

WORKDIR /build

# System dependencies for compiled packages (e.g. aiohttp, uvloop)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime — minimal image with only the venv and app code
FROM python:3.11-slim AS runtime

WORKDIR /app

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY . /app/backend
ENV PYTHONPATH=/app

# Non-root user for security
RUN addgroup --system agentops && adduser --system --group agentops
USER agentops

# Health check
HEALTHCHECK --interval=15s --timeout=10s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

EXPOSE 8000

# Graceful shutdown: uvicorn handles SIGTERM correctly
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--loop", "uvloop"]
