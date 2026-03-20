-- ═══════════════════════════════════════════════════════════════════════════
-- AEGIS-SILENTIUM v12 — Canonical Schema
-- Single source of truth.  app.py, scheduler, and all Go code MUST agree
-- with column names defined here.  Any deviation is a schema-drift bug.
-- Applied automatically by Docker entrypoint on first run.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── nodes ─────────────────────────────────────────────────────────────────
-- Canonical column names — app.py uses EXACTLY these names.
-- node_id   : agent-assigned UUID (primary key)
-- ip_address: remote address as seen by the relay
-- external_ip: operator-supplied external NAT address (optional)
-- hostname  : agent-reported hostname
-- os_type   : platform string (linux/windows/darwin/android)
-- os_version: kernel/OS version string
-- arch      : x86_64 / arm64 / arm / x86
-- username  : running user
-- privilege : "root" | "admin" | "user"
-- is_elevated: True when running as SYSTEM/root
-- capabilities: JSONB — feature flags reported by the agent
-- metadata  : JSONB — arbitrary operator-added tags
-- version   : agent version string
-- status    : active / dormant / dead / killed

CREATE TABLE IF NOT EXISTS nodes (
    node_id         TEXT PRIMARY KEY,
    hostname        TEXT             NOT NULL DEFAULT '',
    os_type         TEXT             NOT NULL DEFAULT '',
    os_version      TEXT             NOT NULL DEFAULT '',
    arch            TEXT             NOT NULL DEFAULT '',
    username        TEXT             NOT NULL DEFAULT '',
    privilege       TEXT             NOT NULL DEFAULT 'user',
    ip_address      TEXT             NOT NULL DEFAULT '',
    external_ip     TEXT             NOT NULL DEFAULT '',
    internal_ips    TEXT[]           NOT NULL DEFAULT '{}',
    is_elevated     BOOLEAN          NOT NULL DEFAULT FALSE,
    capabilities    JSONB            NOT NULL DEFAULT '{}',
    metadata        JSONB            NOT NULL DEFAULT '{}',
    version         TEXT             NOT NULL DEFAULT '',
    status          TEXT             NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','dormant','dead','killed')),
    trust_score     INTEGER          NOT NULL DEFAULT 0
                    CHECK (trust_score BETWEEN 0 AND 100),
    registered_at   TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nodes_status    ON nodes (status);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_nodes_os_type   ON nodes (os_type);

-- ── campaigns ─────────────────────────────────────────────────────────────
-- status column (NOT a boolean active column).
-- Code queries: WHERE status='active'   NOT  WHERE active=true

CREATE TABLE IF NOT EXISTS campaigns (
    id              SERIAL       PRIMARY KEY,
    name            TEXT         NOT NULL,
    description     TEXT         NOT NULL DEFAULT '',
    status          TEXT         NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','paused','closed')),
    operator        TEXT         NOT NULL DEFAULT 'system',
    target_count    INTEGER      NOT NULL DEFAULT 0,
    completion_pct  INTEGER      NOT NULL DEFAULT 0,
    config          JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    closed_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns (status);

-- ── tasks ─────────────────────────────────────────────────────────────────
-- Extra columns required by app.py result processing:
--   logs       : TEXT  — agent task output/log
--   vuln_count : INTEGER — number of vulnerabilities found by this task
--   crit_count : INTEGER — count of CRITICAL vulns
--   duration   : NUMERIC — wall-clock seconds the task ran
-- Status values accepted by app.py:
--   queued / pending / running / completed / failed / cancelled
-- (schema uses these exact values)

CREATE TABLE IF NOT EXISTS tasks (
    id              SERIAL       PRIMARY KEY,
    task_uuid       TEXT         UNIQUE NOT NULL DEFAULT gen_random_uuid()::text,
    campaign_id     INTEGER      REFERENCES campaigns(id) ON DELETE SET NULL,
    assigned_to     TEXT         REFERENCES nodes(node_id) ON DELETE SET NULL,
    target          TEXT         NOT NULL DEFAULT '',
    action          TEXT         NOT NULL DEFAULT 'recon',
    task_type       TEXT         NOT NULL DEFAULT 'shell',
    status          TEXT         NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued','pending','running','completed','failed','cancelled')),
    priority        INTEGER      NOT NULL DEFAULT 5 CHECK (priority BETWEEN 1 AND 10),
    extra_args      JSONB        NOT NULL DEFAULT '{}',
    result          JSONB        NOT NULL DEFAULT '{}',
    logs            TEXT         NOT NULL DEFAULT '',
    vuln_count      INTEGER      NOT NULL DEFAULT 0,
    crit_count      INTEGER      NOT NULL DEFAULT 0,
    duration        NUMERIC(10,3) NOT NULL DEFAULT 0,
    error           TEXT         NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tasks_node_status ON tasks (assigned_to, status);
CREATE INDEX IF NOT EXISTS idx_tasks_status_prio  ON tasks (status, priority DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_campaign     ON tasks (campaign_id);
CREATE INDEX IF NOT EXISTS idx_tasks_uuid         ON tasks (task_uuid);
CREATE INDEX IF NOT EXISTS idx_tasks_created      ON tasks (created_at DESC);

-- ── vulnerabilities ───────────────────────────────────────────────────────
-- CRITICAL: app.py inserts using column name 'details' (plural).
-- Schema MUST use 'details', not 'detail'.

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              BIGSERIAL    PRIMARY KEY,
    task_id         INTEGER      REFERENCES tasks(id) ON DELETE SET NULL,
    node_id         TEXT         REFERENCES nodes(node_id) ON DELETE CASCADE,
    target          TEXT         NOT NULL DEFAULT '',
    url             TEXT         NOT NULL DEFAULT '',
    vuln_type       TEXT         NOT NULL DEFAULT 'unknown',
    severity        TEXT         NOT NULL DEFAULT 'MEDIUM'
                    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    title           TEXT         NOT NULL DEFAULT '',
    details         BYTEA,                -- AES-256-GCM encrypted JSON blob
    payload         TEXT         NOT NULL DEFAULT '',
    evidence        TEXT         NOT NULL DEFAULT '',
    parameter       TEXT         NOT NULL DEFAULT '',
    cvss_score      NUMERIC(4,1),
    cve             TEXT         NOT NULL DEFAULT '',
    remediation     TEXT         NOT NULL DEFAULT '',
    false_positive  BOOLEAN      NOT NULL DEFAULT FALSE,
    status          TEXT         NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','confirmed','false_positive','remediated')),
    found_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulns_node_sev  ON vulnerabilities (node_id, severity);
CREATE INDEX IF NOT EXISTS idx_vulns_target    ON vulnerabilities (target);
CREATE INDEX IF NOT EXISTS idx_vulns_type      ON vulnerabilities (vuln_type);
CREATE INDEX IF NOT EXISTS idx_vulns_found_at  ON vulnerabilities (found_at DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_status    ON vulnerabilities (status);

-- ── events ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id              BIGSERIAL    PRIMARY KEY,
    node_id         TEXT,
    event_type      TEXT         NOT NULL,
    message         TEXT         NOT NULL DEFAULT '',
    severity        TEXT         NOT NULL DEFAULT 'info',
    payload         JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_node    ON events (node_id);
CREATE INDEX IF NOT EXISTS idx_events_type    ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_sev     ON events (severity);
CREATE INDEX IF NOT EXISTS idx_events_created ON events (created_at DESC);

-- ── findings ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL    PRIMARY KEY,
    node_id         TEXT         REFERENCES nodes(node_id) ON DELETE SET NULL,
    task_id         INTEGER      REFERENCES tasks(id) ON DELETE SET NULL,
    kind            TEXT         NOT NULL DEFAULT 'credential',
    severity        TEXT         NOT NULL DEFAULT 'HIGH'
                    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    title           TEXT         NOT NULL,
    description     TEXT         NOT NULL DEFAULT '',
    raw_data        BYTEA,
    source_path     TEXT         NOT NULL DEFAULT '',
    target          TEXT         NOT NULL DEFAULT '',
    tags            TEXT[]       NOT NULL DEFAULT '{}',
    false_positive  BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_node     ON findings (node_id);
CREATE INDEX IF NOT EXISTS idx_findings_kind     ON findings (kind);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_created  ON findings (created_at DESC);

-- ── node_commands ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS node_commands (
    id              SERIAL       PRIMARY KEY,
    node_id         TEXT         REFERENCES nodes(node_id) ON DELETE CASCADE,
    command         TEXT         NOT NULL,
    args            JSONB        NOT NULL DEFAULT '{}',
    status          TEXT         NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','delivered','executed','failed')),
    signed          BOOLEAN      NOT NULL DEFAULT FALSE,
    signature       BYTEA,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    executed_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_cmds_node_status ON node_commands (node_id, status);

-- ── relay_sessions (audit only — keys never stored) ──────────────────────
CREATE TABLE IF NOT EXISTS relay_sessions (
    id              BIGSERIAL    PRIMARY KEY,
    relay_id        TEXT         NOT NULL,
    node_id         TEXT,
    client_nonce    TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_rsess_node ON relay_sessions (node_id);
CREATE INDEX IF NOT EXISTS idx_rsess_ts   ON relay_sessions (created_at DESC);

-- ── exfil_receipts ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS exfil_receipts (
    id              BIGSERIAL    PRIMARY KEY,
    node_id         TEXT         REFERENCES nodes(node_id) ON DELETE SET NULL,
    channel         TEXT         NOT NULL DEFAULT 'https',
    filename        TEXT         NOT NULL DEFAULT '',
    size_bytes      BIGINT       NOT NULL DEFAULT 0,
    checksum        TEXT         NOT NULL DEFAULT '',
    received_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_exfil_node    ON exfil_receipts (node_id);
CREATE INDEX IF NOT EXISTS idx_exfil_channel ON exfil_receipts (channel);

-- ── Retention cleanup ─────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION cleanup_old_data(
    events_days         INT DEFAULT 30,
    relay_sessions_days INT DEFAULT 7
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM events
    WHERE created_at < NOW() - make_interval(days => events_days);

    DELETE FROM relay_sessions
    WHERE created_at < NOW() - make_interval(days => relay_sessions_days);

    DELETE FROM node_commands
    WHERE status IN ('executed','failed')
      AND executed_at < NOW() - INTERVAL '7 days';
END;
$$;

-- ── Updated-at trigger ────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION _set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_campaigns_updated_at') THEN
        CREATE TRIGGER trg_campaigns_updated_at
            BEFORE UPDATE ON campaigns
            FOR EACH ROW EXECUTE FUNCTION _set_updated_at();
    END IF;
END $$;

-- ── Seed ──────────────────────────────────────────────────────────────────
INSERT INTO campaigns (name, description, status, operator)
VALUES ('Default Campaign', 'Default AEGIS-SILENTIUM campaign', 'active', 'bootstrap')
ON CONFLICT DO NOTHING;

DO $$ BEGIN
    RAISE NOTICE 'AEGIS-SILENTIUM v12 schema initialized — all columns canonical.';
END $$;

-- ── exploits ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS exploits (
    id              SERIAL       PRIMARY KEY,
    cve_id          TEXT         UNIQUE,
    name            TEXT         NOT NULL,
    severity        TEXT         NOT NULL DEFAULT 'MEDIUM'
                    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    type            TEXT         NOT NULL DEFAULT 'Custom',
    target          TEXT         NOT NULL DEFAULT 'Web',
    service         TEXT         NOT NULL DEFAULT '',
    auth_required   TEXT         NOT NULL DEFAULT 'None',
    reliability     INTEGER      NOT NULL DEFAULT 50
                    CHECK (reliability BETWEEN 0 AND 100),
    cvss_score      NUMERIC(4,1),
    status          TEXT         NOT NULL DEFAULT 'available'
                    CHECK (status IN ('available','staged','deployed','used','retired')),
    use_count       INTEGER      NOT NULL DEFAULT 0,
    description     TEXT         NOT NULL DEFAULT '',
    notes           TEXT         NOT NULL DEFAULT '',
    deployed_on     TEXT,
    deployed_by     TEXT,
    deployed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_exploits_severity ON exploits (severity);
CREATE INDEX IF NOT EXISTS idx_exploits_status   ON exploits (status);
CREATE INDEX IF NOT EXISTS idx_exploits_type     ON exploits (type);
CREATE INDEX IF NOT EXISTS idx_exploits_cvss     ON exploits (cvss_score DESC NULLS LAST);

-- ── listeners ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS listeners (
    id              SERIAL       PRIMARY KEY,
    listener_id     TEXT         UNIQUE NOT NULL,
    name            TEXT         NOT NULL,
    type            TEXT         NOT NULL DEFAULT 'http'
                    CHECK (type IN ('http','https','tcp','dns','smb','websocket')),
    host            TEXT         NOT NULL DEFAULT '0.0.0.0',
    port            INTEGER      NOT NULL,
    status          TEXT         NOT NULL DEFAULT 'stopped'
                    CHECK (status IN ('running','stopped','error','starting')),
    config          JSONB        NOT NULL DEFAULT '{}',
    operator        TEXT         NOT NULL DEFAULT 'system',
    sessions_total  INTEGER      NOT NULL DEFAULT 0,
    bytes_rx        BIGINT       NOT NULL DEFAULT 0,
    bytes_tx        BIGINT       NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_listeners_status ON listeners (status);
CREATE INDEX IF NOT EXISTS idx_listeners_type   ON listeners (type);

-- ── generated_payloads ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS generated_payloads (
    id              SERIAL       PRIMARY KEY,
    build_id        TEXT         UNIQUE NOT NULL,
    payload_type    TEXT         NOT NULL,
    output_format   TEXT         NOT NULL DEFAULT 'Windows EXE',
    architecture    TEXT         NOT NULL DEFAULT 'x86_64',
    obfuscation     TEXT         NOT NULL DEFAULT 'None',
    listener_id     TEXT,
    operator        TEXT         NOT NULL DEFAULT 'system',
    campaign_id     INTEGER      REFERENCES campaigns(id) ON DELETE SET NULL,
    status          TEXT         NOT NULL DEFAULT 'building'
                    CHECK (status IN ('building','ready','deployed','retired','failed')),
    size_bytes      INTEGER      NOT NULL DEFAULT 0,
    sha256          TEXT         NOT NULL DEFAULT '',
    build_log       TEXT         NOT NULL DEFAULT '',
    options         JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_payloads_status   ON generated_payloads (status);
CREATE INDEX IF NOT EXISTS idx_payloads_operator ON generated_payloads (operator);
CREATE INDEX IF NOT EXISTS idx_payloads_campaign ON generated_payloads (campaign_id);

-- ── surveillance_targets ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS surveillance_targets (
    id              SERIAL       PRIMARY KEY,
    node_id         TEXT         REFERENCES nodes(node_id) ON DELETE CASCADE,
    label           TEXT         NOT NULL DEFAULT '',
    platform        TEXT         NOT NULL DEFAULT 'android',
    status          TEXT         NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','inactive','lost')),
    operator        TEXT         NOT NULL DEFAULT 'system',
    data_collected_mb NUMERIC(10,2) NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_surv_targets_node ON surveillance_targets (node_id);

-- ── surveillance_modules ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS surveillance_modules (
    id              SERIAL       PRIMARY KEY,
    target_id       INTEGER      REFERENCES surveillance_targets(id) ON DELETE CASCADE,
    module_type     TEXT         NOT NULL,
    status          TEXT         NOT NULL DEFAULT 'idle'
                    CHECK (status IN ('idle','active','error')),
    config          JSONB        NOT NULL DEFAULT '{}',
    last_data       BYTEA,
    last_data_at    TIMESTAMPTZ,
    bytes_collected BIGINT       NOT NULL DEFAULT 0,
    activated_at    TIMESTAMPTZ,
    UNIQUE (target_id, module_type)
);
CREATE INDEX IF NOT EXISTS idx_surv_modules_target ON surveillance_modules (target_id, status);

-- ── teamchat_messages ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS teamchat_messages (
    id              BIGSERIAL    PRIMARY KEY,
    channel         TEXT         NOT NULL DEFAULT 'general',
    operator        TEXT         NOT NULL,
    message         TEXT         NOT NULL,
    message_type    TEXT         NOT NULL DEFAULT 'text'
                    CHECK (message_type IN ('text','system','alert','file')),
    pinned          BOOLEAN      NOT NULL DEFAULT FALSE,
    deleted         BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_chat_channel   ON teamchat_messages (channel, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_operator  ON teamchat_messages (operator);
CREATE INDEX IF NOT EXISTS idx_chat_pinned    ON teamchat_messages (channel) WHERE pinned = TRUE;

-- ── operator_presence ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS operator_presence (
    operator        TEXT         PRIMARY KEY,
    last_seen_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    ip              TEXT         NOT NULL DEFAULT ''
);

DO $$ BEGIN
    RAISE NOTICE 'AEGIS-SILENTIUM v12 — extended schema applied (exploits, listeners, payloads, surveillance, teamchat).';
END $$;
