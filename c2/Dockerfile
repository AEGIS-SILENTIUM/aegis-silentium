# ════════════════════════════════════════════════════════════════════════
# AEGIS-Advanced — C2 Server Dockerfile
# ════════════════════════════════════════════════════════════════════════
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev libssl-dev libpq-dev python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip wheel && \
    pip install --prefix=/install --no-warn-script-location \
        flask flask-cors gunicorn gevent \
        redis psycopg2-binary \
        cryptography \
        requests \
        orjson rich \
    2>/dev/null || true

# ── Runtime ──────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="AEGIS-Advanced" version="4.0-APEX" \
      description="AEGIS Command & Control Server"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl openssl ca-certificates procps net-tools iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

COPY c2/      /app/c2/
COPY shared/  /app/shared/
COPY configs/ /app/configs/

RUN mkdir -p /logs /certs

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# C2 defaults
ENV C2_SECRET=change-this-strong-secret-2026
ENV OPERATOR_KEY=aegis-operator-key-2026
ENV REDIS_HOST=redis
ENV POSTGRES_HOST=postgres
ENV POSTGRES_DB=aegis
ENV POSTGRES_USER=aegis
ENV POSTGRES_PASSWORD=aegissecret2026
ENV BEACON_LPOLL=25
ENV MESH_PORT=5001
ENV MAX_RATE=120

HEALTHCHECK --interval=15s --timeout=5s --start-period=45s --retries=5 \
    CMD curl -sf http://localhost:5000/api/stats || exit 1

EXPOSE 5000 5001/udp 8080

VOLUME ["/logs", "/certs"]

WORKDIR /app/c2
# Use gunicorn with gevent for production async (SSE-friendly)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", \
     "--worker-class", "gevent", \
     "--workers", "4", \
     "--worker-connections", "1000", \
     "--timeout", "120", \
     "--keep-alive", "75", \
     "--log-level", "info", \
     "--access-logfile", "/logs/c2-access.log", \
     "--error-logfile", "/logs/c2-error.log", \
     "app:app"]
