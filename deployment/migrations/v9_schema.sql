-- ═══════════════════════════════════════════════════════════════════════════
-- AEGIS-SILENTIUM v9 — Schema Migration
-- Idempotent: safe to run multiple times.  All changes are additive.
-- Run order: after v8 init.sql
-- ═══════════════════════════════════════════════════════════════════════════

-- ── OPERATORS ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS operators (
    id              SERIAL PRIMARY KEY,
    handle          VARCHAR(64)  UNIQUE NOT NULL,
    key_hash        TEXT         NOT NULL,          -- PBKDF2-HMAC-SHA256 "salt$hash"
    role            VARCHAR(16)  NOT NULL DEFAULT 'operator'
                    CHECK (role IN ('ghost','operator','senior','lead','admin')),
    active          BOOLEAN      NOT NULL DEFAULT TRUE,
    failed_logins   INTEGER      NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_login_at   TIMESTAMPTZ,
    last_ip         VARCHAR(64),
    created_by      VARCHAR(64)  NOT NULL DEFAULT 'bootstrap',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_operators_handle ON operators (handle);
CREATE INDEX IF NOT EXISTS idx_operators_role   ON operators (role);
CREATE INDEX IF NOT EXISTS idx_operators_active ON operators (active) WHERE active = TRUE;

-- ── OPERATOR AUDIT TRAIL ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS operator_audit (
    id          BIGSERIAL   PRIMARY KEY,
    operator    VARCHAR(64) NOT NULL,
    action      VARCHAR(64) NOT NULL,
    detail      TEXT        NOT NULL DEFAULT '',
    ip          VARCHAR(64) NOT NULL DEFAULT '',
    user_agent  TEXT        NOT NULL DEFAULT '',
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_operator ON operator_audit (operator, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action   ON operator_audit (action, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ts       ON operator_audit (ts DESC);

-- Retain audit records for 1 year (enforced by retention job)
ALTER TABLE operator_audit ADD COLUMN IF NOT EXISTS retain_until TIMESTAMPTZ
    GENERATED ALWAYS AS (ts + INTERVAL '365 days') STORED;

-- ── SECRET STORE ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS secret_store (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(64)  NOT NULL,
    version     VARCHAR(16)  NOT NULL DEFAULT 'current',
    value       TEXT         NOT NULL,
    updated_by  VARCHAR(64)  NOT NULL DEFAULT 'system',
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS secret_audit (
    id           SERIAL PRIMARY KEY,
    secret_name  VARCHAR(64)  NOT NULL,
    action       VARCHAR(32)  NOT NULL,
    rotated_by   VARCHAR(64)  NOT NULL DEFAULT 'system',
    ts           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secret_audit_name ON secret_audit (secret_name, ts DESC);

-- ── WEBHOOKS ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhooks (
    id          SERIAL PRIMARY KEY,
    webhook_id  VARCHAR(16) UNIQUE NOT NULL,
    url         TEXT        NOT NULL,
    events      TEXT        NOT NULL DEFAULT '["*"]',  -- JSON array of glob patterns
    secret      TEXT        NOT NULL DEFAULT '',
    description TEXT        NOT NULL DEFAULT '',
    created_by  VARCHAR(64) NOT NULL DEFAULT 'operator',
    active      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id            BIGSERIAL   PRIMARY KEY,
    webhook_id    VARCHAR(16) NOT NULL REFERENCES webhooks(webhook_id) ON DELETE CASCADE,
    delivery_id   VARCHAR(12) NOT NULL,
    event_type    VARCHAR(64) NOT NULL,
    attempt       INTEGER     NOT NULL DEFAULT 1,
    status_code   INTEGER,
    error         TEXT        NOT NULL DEFAULT '',
    attempted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (webhook_id, delivery_id, attempt)
);

CREATE INDEX IF NOT EXISTS idx_wh_deliveries_webhook ON webhook_deliveries (webhook_id, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_wh_deliveries_status  ON webhook_deliveries (status_code);

-- ── DATA RETENTION LOG ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS retention_runs (
    id          SERIAL PRIMARY KEY,
    table_name  VARCHAR(64) NOT NULL,
    rows_deleted INTEGER     NOT NULL DEFAULT 0,
    ran_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_ms INTEGER     NOT NULL DEFAULT 0
);

-- ── SESSIONS TABLE (optional — for cross-process revocation without Redis) ───
CREATE TABLE IF NOT EXISTS operator_sessions (
    jti         VARCHAR(32) PRIMARY KEY,
    handle      VARCHAR(64) NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at  TIMESTAMPTZ,
    ip          VARCHAR(64) NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_handle  ON operator_sessions (handle);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON operator_sessions (expires_at);

-- ── ALERTS TABLE (for Prometheus alert routing / incident tracking) ──────────
CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL   PRIMARY KEY,
    name        VARCHAR(128) NOT NULL,
    severity    VARCHAR(16)  NOT NULL DEFAULT 'info'
                CHECK (severity IN ('info','warning','critical')),
    message     TEXT         NOT NULL,
    labels      JSONB        NOT NULL DEFAULT '{}',
    status      VARCHAR(16)  NOT NULL DEFAULT 'firing'
                CHECK (status IN ('firing','resolved','acknowledged')),
    acknowledged_by VARCHAR(64),
    acknowledged_at TIMESTAMPTZ,
    fired_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts (status, fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity) WHERE status = 'firing';

-- ── UPDATED_AT TRIGGERS (apply to all tables that have the column) ───────────
CREATE OR REPLACE FUNCTION _set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

DO $$
DECLARE tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['operators', 'listeners'] LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname = 'trg_' || tbl || '_updated_at'
        ) THEN
            EXECUTE format(
                'CREATE TRIGGER trg_%I_updated_at BEFORE UPDATE ON %I '
                'FOR EACH ROW EXECUTE FUNCTION _set_updated_at()', tbl, tbl
            );
        END IF;
    END LOOP;
END; $$;

-- ── SEED: bootstrap admin operator ───────────────────────────────────────────
-- Key hash for 'aegis-operator-key-2026' — REPLACE IN PRODUCTION
-- Generated with: _hash_key('aegis-operator-key-2026')
-- The real hash is set at runtime via SecretManager.create_operator()
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM operators WHERE handle = 'r00t_handler') THEN
        INSERT INTO operators (handle, key_hash, role, created_by)
        VALUES (
            'r00t_handler',
            'bootstrap_placeholder$replace_at_runtime_via_create_operator_api',
            'admin',
            'bootstrap'
        );
    END IF;
END; $$;

DO $$ BEGIN
    RAISE NOTICE 'AEGIS-SILENTIUM v9 schema applied.';
END $$;
