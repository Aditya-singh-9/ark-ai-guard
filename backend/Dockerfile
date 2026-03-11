# ─────────────────────────────────────────────────────────────────────────────
# ARK DevSecOps AI — Backend Dockerfile
# Multi-stage build: installs security tools + Python deps, then copies source.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Security Tools Builder ──────────────────────────────────────────
FROM python:3.11-slim AS tools-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    tar \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy (Aquasecurity vulnerability scanner)
RUN TRIVY_VERSION="0.57.1" && \
    wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -O /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz && \
    trivy --version

# ── Stage 2: Python Dependencies ─────────────────────────────────────────────
FROM python:3.11-slim AS python-builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Stage 3: Final Runtime Image ──────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Non-root user for security
RUN groupadd --gid 1001 ark && \
    useradd --uid 1001 --gid ark --shell /bin/bash --create-home ark

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Trivy from builder
COPY --from=tools-builder /usr/local/bin/trivy /usr/local/bin/trivy

# Copy Python packages from builder
COPY --from=python-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python-builder /usr/local/bin /usr/local/bin

# Install Semgrep and Bandit (lighter tools, installed in final stage)
RUN pip install --no-cache-dir semgrep==1.100.0 bandit==1.8.3 pip-audit==2.8.0

# Create scan temp dir
RUN mkdir -p /tmp/ark-scans && chown ark:ark /tmp/ark-scans

# Set working directory
WORKDIR /app
RUN chown ark:ark /app

# Copy application source
COPY --chown=ark:ark . /app/

# Switch to non-root user
USER ark

# Environment defaults (override via docker-compose or k8s secrets)
ENV APP_ENV=production \
    DEBUG=false \
    SCAN_TEMP_DIR=/tmp/ark-scans \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start uvicorn with production settings
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--loop", "uvloop", \
     "--access-log", \
     "--log-level", "info"]
