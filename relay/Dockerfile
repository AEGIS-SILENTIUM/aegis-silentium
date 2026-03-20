# ─── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
# Build hardened binary: strip debug info, trimpath, no CGO
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -ldflags="-s -w -extldflags=-static" \
    -trimpath \
    -o relay \
    ./main.go

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM scratch

# Copy timezone data and CA certs for TLS
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/relay /relay

# Non-root execution
USER 65534:65534

# Relay listens on 443 (TLS)
EXPOSE 443

# Volumes for certs, config, profiles
VOLUME ["/config", "/certs", "/profiles"]

ENTRYPOINT ["/relay", "--config", "/config/relay.yaml"]

# ─── Labels ───────────────────────────────────────────────────────────────────
LABEL org.opencontainers.image.title="AEGIS-Omega Relay"
LABEL org.opencontainers.image.description="Stateless ECDHE relay — AUTHORIZED USE ONLY"
LABEL org.opencontainers.image.version="5.0-omega"
