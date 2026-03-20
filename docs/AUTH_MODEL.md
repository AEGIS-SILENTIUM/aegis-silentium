# AEGIS-SILENTIUM v12 — Authentication Model

## Overview

AEGIS-SILENTIUM uses a single authoritative authentication path: **JWT Bearer tokens**.
All legacy and alternative auth paths have been removed to eliminate attack surface.

## Active Authentication Paths

### 1. JWT Login (Primary — all clients)
```
POST /api/auth/login
{"handle": "alice", "operator_key": "<48-char key>"}
→ {"access_token": "...", "refresh_token": "...", "expires_in": 900, "role": "operator"}
```
- Access token: 15-minute lifetime
- Refresh token: 7-day lifetime, single-use, stored server-side

### 2. Token Refresh
```
POST /api/auth/refresh
{"refresh_token": "..."}
→ {"access_token": "...", "expires_in": 900}
```

### 3. Per-Operator API Keys (long-lived)
```
POST /api/auth/keys         # issue new key
POST /api/auth/keys/revoke  # revoke specific key
```
API keys are validated via the same `Authorization: Bearer <key>` header.
They are SHA-256 hashed in Redis — raw key is never stored.

### 4. TOTP MFA (optional)
```
POST /api/auth/totp/setup   # generate TOTP secret + QR URI
POST /api/auth/totp/verify  # activate MFA for operator account
```

## Removed Auth Paths

| Path | Why Removed |
|------|-------------|
| `X-Aegis-Key` header | Granted admin-level access via single header value |
| `?key=` query string | Tokens in URLs appear in logs, referrers, caches |
| `AEGIS_ALLOW_KEY_AUTH=1` env flag | Single shared key with no granularity or revocation |

## Token Storage

- **Server**: JTI stored in Redis with TTL; revocation deletes the Redis key
- **Dashboard**: Access + refresh tokens in JavaScript memory variables only  
  (never written to `sessionStorage` or `localStorage`)
- **Node**: Tokens in process memory only

## Roles and Permissions

| Role | Permissions |
|------|-------------|
| `ghost` | Read-only: view sessions, tasks, campaigns, exploits |
| `operator` | ghost + create tasks, chat, generate payloads, nodes:view/command |
| `senior` | operator + kill sessions/nodes, admin:read/write |
| `lead` | senior + all operational controls |
| `admin` | All permissions |

## Security Properties

- Constant-time comparison on all token verification (HMAC-safe)
- Failed auth attempts are logged with IP and reason
- Rate limiting: 5 attempts per 15 minutes per IP before lockout
- JWT signed with HS256 using a randomly generated secret (rotatable via API)
