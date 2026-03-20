# ════════════════════════════════════════════════════════════════════════
# AEGIS-Advanced — Scheduler Dockerfile
# ════════════════════════════════════════════════════════════════════════
FROM python:3.12-slim AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev libssl-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip wheel && \
    pip install --prefix=/install --no-warn-script-location \
        redis psycopg2-binary \
        cryptography orjson \
    2>/dev/null || true

# ── Runtime ──────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="AEGIS-Advanced" version="4.0-APEX" \
      description="AEGIS Campaign Scheduler"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY scheduler/ /app/scheduler/
COPY shared/    /app/shared/

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENV REDIS_HOST=redis
ENV REDIS_PASSWORD=
ENV POSTGRES_HOST=postgres
ENV POSTGRES_DB=aegis
ENV POSTGRES_USER=aegis
ENV POSTGRES_PASSWORD=aegissecret2026
ENV RESCAN_INTERVAL_HOURS=24
ENV STALE_TASK_TIMEOUT_MIN=30
ENV DEAD_NODE_MINUTES=10
ENV SCHEDULER_CYCLE_SECONDS=60
ENV MAX_PENDING_TASKS=5000
ENV MAX_TASKS_PER_HOUR=500

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD pgrep -f "python.*app.py" > /dev/null || exit 1

WORKDIR /app/scheduler
CMD ["python3", "-u", "app.py"]
