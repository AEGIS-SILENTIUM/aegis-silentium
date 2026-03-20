# ════════════════════════════════════════════════════════════════════════
# AEGIS-Advanced — Node Worker Dockerfile
# ════════════════════════════════════════════════════════════════════════
# Multi-stage build: builder installs deps, runtime is minimal
# Final image: ~450MB (Python 3.12 slim + all scan tools)
# ════════════════════════════════════════════════════════════════════════

# ── Stage 1: Builder ──────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

LABEL stage=builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    libpq-dev \
    libpcap-dev \
    python3-dev \
    cargo \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .

# Install in two passes: fast packages first, then slow ones
RUN pip install --upgrade pip wheel setuptools && \
    pip install --prefix=/install --no-warn-script-location \
        flask flask-cors \
        redis psycopg2-binary \
        cryptography \
        requests aiohttp aiofiles \
        paramiko \
        beautifulsoup4 lxml \
        scikit-learn numpy \
        dnspython \
        rich PyYAML python-dotenv \
        orjson \
    2>/dev/null || true && \
    pip install --prefix=/install --no-warn-script-location \
        shodan \
    2>/dev/null || true

# ── Stage 2: Runtime ──────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="AEGIS-Advanced" \
      version="4.0-APEX" \
      description="AEGIS Distributed Scan Node"

WORKDIR /app

# Install runtime system tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools
    curl \
    wget \
    nmap \
    masscan \
    netcat-openbsd \
    socat \
    dnsutils \
    iputils-ping \
    traceroute \
    net-tools \
    iproute2 \
    # SSL tools
    openssl \
    ca-certificates \
    # Process tools
    procps \
    htop \
    # File tools
    file \
    zip \
    unzip \
    # SSH client
    openssh-client \
    # Misc
    git \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy built Python packages
COPY --from=builder /install /usr/local

# ── Application code ─────────────────────────────────────────────────────
# Copy the full project (only what the node needs)
COPY node/            /app/node/
COPY shared/          /app/shared/
COPY configs/         /app/configs/

# Create necessary directories
RUN mkdir -p /reports /logs /tmp/aegis

# Set Python path so imports work
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default environment (all overridable at runtime)
ENV C2_URL=http://c2:5000
ENV C2_SECRET=change-this-strong-secret-2026
ENV NODE_ID=node-auto
ENV REPORTS_DIR=/reports
ENV HB_INTERVAL=30
ENV TASK_INTERVAL=5
ENV MAX_PARALLEL=2
ENV SCAN_THREADS=50
ENV SCAN_DEPTH=3

# Security: run as non-root (uncomment for hardened deployments)
# RUN useradd -r -u 1001 -g root aegis
# RUN chown -R aegis:root /app /reports /logs
# USER aegis

# Health check — verifies agent is running and not hung
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD pgrep -f "python.*app.py" > /dev/null || exit 1

VOLUME ["/reports", "/logs"]

# Entry point
WORKDIR /app/node
CMD ["python3", "-u", "app.py"]
