# ════════════════════════════════════════════════════════════════════════
# AEGIS-Advanced — Dashboard Dockerfile
# ════════════════════════════════════════════════════════════════════════
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev libssl-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip wheel && \
    pip install --prefix=/install --no-warn-script-location \
        flask flask-cors gunicorn gevent \
        redis \
        cryptography \
        requests \
        orjson \
    2>/dev/null || true

# ── Runtime ──────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="AEGIS-Advanced" version="4.0-APEX" \
      description="AEGIS Operator Dashboard"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl openssl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

COPY dashboard/ /app/dashboard/
COPY shared/    /app/shared/

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENV C2_URL=http://c2:5000
ENV OPERATOR_KEY=aegis-operator-key-2026
ENV REDIS_HOST=redis
ENV REDIS_PASSWORD=
ENV PORT=7331

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -sf http://localhost:7331/ || exit 1

EXPOSE 7331

WORKDIR /app/dashboard
CMD ["gunicorn", "--bind", "0.0.0.0:7331", \
     "--worker-class", "gevent", \
     "--workers", "2", \
     "--worker-connections", "500", \
     "--timeout", "300", \
     "--keep-alive", "75", \
     "--log-level", "warning", \
     "app:app"]
