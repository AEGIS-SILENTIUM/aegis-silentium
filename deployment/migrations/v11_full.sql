-- ─────────────────────────────────────────────────────────────────────────────
-- AEGIS-SILENTIUM v11 — Database Migration
-- File: deployment/migrations/v11_full.sql
-- Applies on top of v10_distributed.sql
-- ─────────────────────────────────────────────────────────────────────────────

BEGIN;

-- ── IOC Manager ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iocs (
    ioc_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_type        VARCHAR(32)  NOT NULL,
    value           TEXT         NOT NULL,
    value_normalised TEXT        NOT NULL,
    confidence      NUMERIC(4,3) NOT NULL DEFAULT 0.8 CHECK (confidence BETWEEN 0 AND 1),
    severity        VARCHAR(16)  NOT NULL DEFAULT 'medium',
    source          VARCHAR(128) NOT NULL DEFAULT 'manual',
    tags            TEXT[]       NOT NULL DEFAULT '{}',
    description     TEXT         NOT NULL DEFAULT '',
    ttl_seconds     INTEGER,                               -- NULL = no expiry
    hit_count       INTEGER      NOT NULL DEFAULT 0,
    active          BOOLEAN      NOT NULL DEFAULT TRUE,
    meta            JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ GENERATED ALWAYS AS (
        CASE WHEN ttl_seconds IS NOT NULL
             THEN created_at + (ttl_seconds || ' seconds')::INTERVAL
        END
    ) STORED
);
CREATE INDEX IF NOT EXISTS idx_iocs_type     ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_value    ON iocs(value_normalised);
CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
CREATE INDEX IF NOT EXISTS idx_iocs_active   ON iocs(active) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_iocs_tags     ON iocs USING GIN(tags);

-- ── MITRE ATT&CK Observations ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ttp_observations (
    obs_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    technique_id  VARCHAR(16)  NOT NULL,
    campaign_id   INTEGER      REFERENCES campaigns(id) ON DELETE SET NULL,
    node_id       VARCHAR(64),
    confidence    NUMERIC(4,3) NOT NULL DEFAULT 0.8,
    evidence      TEXT         NOT NULL DEFAULT '',
    operator      VARCHAR(64),
    tags          TEXT[]       NOT NULL DEFAULT '{}',
    observed_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ttp_technique  ON ttp_observations(technique_id);
CREATE INDEX IF NOT EXISTS idx_ttp_campaign   ON ttp_observations(campaign_id);
CREATE INDEX IF NOT EXISTS idx_ttp_node       ON ttp_observations(node_id);

-- ── Threat Graph ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_nodes (
    node_id     VARCHAR(128) PRIMARY KEY,
    kind        VARCHAR(32)  NOT NULL DEFAULT 'ioc',
    data        JSONB        NOT NULL DEFAULT '{}',
    score       NUMERIC(10,6) NOT NULL DEFAULT 1.0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_edges (
    edge_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id   VARCHAR(128) NOT NULL REFERENCES threat_nodes(node_id) ON DELETE CASCADE,
    target_id   VARCHAR(128) NOT NULL REFERENCES threat_nodes(node_id) ON DELETE CASCADE,
    edge_type   VARCHAR(32)  NOT NULL,
    confidence  NUMERIC(4,3) NOT NULL DEFAULT 0.7,
    evidence    TEXT         NOT NULL DEFAULT '',
    meta        JSONB        NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tedge_source ON threat_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_tedge_target ON threat_edges(target_id);

-- ── Saga Orchestrator ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sagas (
    saga_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    saga_type   VARCHAR(64)  NOT NULL,
    state       VARCHAR(32)  NOT NULL DEFAULT 'pending',
    context     JSONB        NOT NULL DEFAULT '{}',
    steps       JSONB        NOT NULL DEFAULT '[]',
    error       TEXT         NOT NULL DEFAULT '',
    operator    VARCHAR(64),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_saga_type  ON sagas(saga_type);
CREATE INDEX IF NOT EXISTS idx_saga_state ON sagas(state);

-- ── Service Registry ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS service_instances (
    service_id    VARCHAR(128) PRIMARY KEY,
    service_name  VARCHAR(64)  NOT NULL,
    address       VARCHAR(256) NOT NULL,
    port          INTEGER      NOT NULL,
    tags          TEXT[]       NOT NULL DEFAULT '{}',
    meta          JSONB        NOT NULL DEFAULT '{}',
    state         VARCHAR(16)  NOT NULL DEFAULT 'unknown',
    weight        INTEGER      NOT NULL DEFAULT 1,
    ttl_seconds   NUMERIC(10,2) NOT NULL DEFAULT 30,
    version       VARCHAR(32)  NOT NULL DEFAULT '',
    registered_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_svc_name  ON service_instances(service_name);
CREATE INDEX IF NOT EXISTS idx_svc_state ON service_instances(state);

-- ── Network Topology ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS network_nodes (
    node_id     VARCHAR(128) PRIMARY KEY,
    ip          INET         NOT NULL,
    hostname    VARCHAR(256),
    mac         VARCHAR(17),
    os_info     TEXT         NOT NULL DEFAULT '',
    open_ports  INTEGER[]    NOT NULL DEFAULT '{}',
    services    JSONB        NOT NULL DEFAULT '{}',
    role        VARCHAR(32)  NOT NULL DEFAULT 'unknown',
    subnet      CIDR,
    is_alive    BOOLEAN      NOT NULL DEFAULT TRUE,
    tags        TEXT[]       NOT NULL DEFAULT '{}',
    meta        JSONB        NOT NULL DEFAULT '{}',
    last_seen   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_netnode_ip   ON network_nodes(ip);
CREATE INDEX IF NOT EXISTS idx_netnode_role ON network_nodes(role);

CREATE TABLE IF NOT EXISTS network_edges (
    edge_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    src_id        VARCHAR(128) NOT NULL REFERENCES network_nodes(node_id) ON DELETE CASCADE,
    dst_id        VARCHAR(128) NOT NULL REFERENCES network_nodes(node_id) ON DELETE CASCADE,
    latency_ms    NUMERIC(10,3) NOT NULL DEFAULT 0,
    bandwidth     NUMERIC(10,3) NOT NULL DEFAULT 0,
    protocol      VARCHAR(16)  NOT NULL DEFAULT '',
    port          INTEGER,
    weight        NUMERIC(10,4) NOT NULL DEFAULT 1.0,
    bidirectional BOOLEAN      NOT NULL DEFAULT TRUE,
    last_seen     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Scan Results ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_results (
    scan_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip          INET         NOT NULL,
    port        INTEGER      NOT NULL,
    state       VARCHAR(16)  NOT NULL,
    service     VARCHAR(64)  NOT NULL DEFAULT '',
    banner      TEXT         NOT NULL DEFAULT '',
    latency_ms  NUMERIC(10,3) NOT NULL DEFAULT 0,
    scanned_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    campaign_id INTEGER      REFERENCES campaigns(id) ON DELETE SET NULL,
    operator    VARCHAR(64)
);
CREATE INDEX IF NOT EXISTS idx_scan_ip      ON scan_results(ip);
CREATE INDEX IF NOT EXISTS idx_scan_port    ON scan_results(port);
CREATE INDEX IF NOT EXISTS idx_scan_state   ON scan_results(state);

-- ── Plugin Audit Log ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS plugin_audit (
    id          SERIAL PRIMARY KEY,
    plugin_id   VARCHAR(128) NOT NULL,
    action      VARCHAR(32)  NOT NULL,  -- loaded / enabled / disabled / error
    operator    VARCHAR(64),
    detail      TEXT         NOT NULL DEFAULT '',
    ts          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Consensus / Raft Log (persistent backing) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS raft_log (
    idx         BIGINT       PRIMARY KEY,
    term        BIGINT       NOT NULL,
    entry_type  VARCHAR(16)  NOT NULL DEFAULT 'data',
    command     JSONB        NOT NULL DEFAULT '{}',
    entry_id    UUID         NOT NULL DEFAULT gen_random_uuid(),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS raft_state (
    node_id     VARCHAR(64)  PRIMARY KEY,
    current_term BIGINT      NOT NULL DEFAULT 0,
    voted_for   VARCHAR(64),
    commit_index BIGINT      NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Streaming Event Log (durable sink) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS event_log (
    offset      BIGSERIAL    PRIMARY KEY,
    topic       VARCHAR(128) NOT NULL,
    event_type  VARCHAR(128) NOT NULL,
    payload     JSONB        NOT NULL DEFAULT '{}',
    key         VARCHAR(256),
    source      VARCHAR(64)  NOT NULL DEFAULT '',
    tags        TEXT[]       NOT NULL DEFAULT '{}',
    event_id    UUID         NOT NULL DEFAULT gen_random_uuid(),
    ts          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_evlog_topic   ON event_log(topic);
CREATE INDEX IF NOT EXISTS idx_evlog_type    ON event_log(event_type);
CREATE INDEX IF NOT EXISTS idx_evlog_ts      ON event_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_evlog_key     ON event_log(key) WHERE key IS NOT NULL;

-- ── Epoch/Fencing Audit ──────────────────────────────────────────────────────
ALTER TABLE fencing_audit ADD COLUMN IF NOT EXISTS resource VARCHAR(64) NOT NULL DEFAULT 'global';
ALTER TABLE fencing_audit ADD COLUMN IF NOT EXISTS reason   TEXT        NOT NULL DEFAULT '';
ALTER TABLE fencing_audit ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- ── WAL enhanced columns ─────────────────────────────────────────────────────
ALTER TABLE wal_entries ADD COLUMN IF NOT EXISTS segment_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE wal_entries ADD COLUMN IF NOT EXISTS entry_type VARCHAR(16) NOT NULL DEFAULT 'data';
ALTER TABLE wal_entries ADD COLUMN IF NOT EXISTS checksum   VARCHAR(8);

-- ── Functions & triggers ─────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_iocs_updated_at') THEN
    CREATE TRIGGER trg_iocs_updated_at
      BEFORE UPDATE ON iocs
      FOR EACH ROW EXECUTE FUNCTION update_updated_at();
  END IF;
END $$;

-- ── Materialized views ────────────────────────────────────────────────────────
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_ioc_summary AS
SELECT
    ioc_type,
    severity,
    COUNT(*)             AS count,
    AVG(confidence)      AS avg_confidence,
    SUM(hit_count)       AS total_hits,
    MAX(last_seen)       AS last_hit
FROM iocs
WHERE active = TRUE AND (expires_at IS NULL OR expires_at > NOW())
GROUP BY ioc_type, severity
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_ioc_summary
    ON mv_ioc_summary(ioc_type, severity);

-- Refresh can be triggered on demand or via pg_cron
COMMENT ON MATERIALIZED VIEW mv_ioc_summary IS
    'Refresh with: REFRESH MATERIALIZED VIEW CONCURRENTLY mv_ioc_summary;';

-- ── Schema version record ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schema_versions (
    version     VARCHAR(16) PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT        NOT NULL DEFAULT ''
);
INSERT INTO schema_versions(version, description)
VALUES ('v11.0', 'AEGIS-SILENTIUM v11 — IOC, MITRE, Raft, Saga, ServiceRegistry, EventLog, Topology')
ON CONFLICT (version) DO NOTHING;

COMMIT;
