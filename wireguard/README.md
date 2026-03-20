# AEGIS-SILENTIUM WireGuard Channel

This directory contains configuration templates for the WireGuard VPN that
creates the secure, authenticated channel between Relays and the Intelligence Core.

## Architecture

```
Implant ──TLS 1.3──► Relay (public) ──WireGuard──► Core (private)
                        │                              │
                    Malleable C2                  PostgreSQL +
                    ECDHE Session               Encrypted DB
```

## Quick Setup

Use the provided script for guided setup:

```bash
bash scripts/setup_wireguard.sh
```

## Manual Setup

### 1. Install WireGuard

```bash
# Debian/Ubuntu
apt install wireguard wireguard-tools

# RHEL/CentOS
dnf install wireguard-tools

# Alpine (Docker)
apk add wireguard-tools
```

### 2. Generate key pairs (run on each host)

```bash
# On Core
wg genkey | tee /etc/wireguard/core_private.key | wg pubkey > /etc/wireguard/core_public.key

# On each Relay
wg genkey | tee /etc/wireguard/relay_private.key | wg pubkey > /etc/wireguard/relay_public.key
chmod 600 /etc/wireguard/relay_private.key /etc/wireguard/core_private.key
```

### 3. Configure interfaces

Copy `wg0.conf.template` to `/etc/wireguard/wg0.conf` on each host and:
- Replace all `*_PLACEHOLDER` values with actual generated keys
- Set `CORE_PUBLIC_IP` to the Core's public IP
- Assign each relay a unique IP (10.99.0.2, 10.99.0.3, ...)

### 4. Start WireGuard

```bash
wg-quick up wg0
systemctl enable wg-quick@wg0
```

### 5. Verify connectivity

```bash
# On relay
ping 10.99.0.1
wg show

# On core
wg show
```

## Firewall Rules

The Core's WireGuard `PostUp` rule blocks direct internet access to port 5000.
Only traffic arriving via `wg0` (10.99.0.0/24) can reach the Core API:

```bash
# Additional hardening on Core
iptables -A INPUT -p tcp --dport 5000 ! -i wg0 -j DROP
iptables -A INPUT -p tcp --dport 5432 ! -i lo -j DROP  # PostgreSQL local only
```

## Security Notes

- WireGuard private keys must never be committed to version control.
- Use short-lived infrastructure: rebuild relays regularly with new keys.
- The Command Node peer has no `PersistentKeepalive` — it connects only when
  injecting signed objectives, then disconnects immediately.
- Relay compromise exposes only the current in-memory ECDHE sessions
  (not past traffic — PFS) and the relay's WireGuard key.
  Rotate WireGuard keys immediately if a relay is suspected compromised.
