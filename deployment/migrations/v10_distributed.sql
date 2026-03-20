-- AEGIS-SILENTIUM v10 Schema Migration
-- Adds distributed systems tables to the existing v9 schema

-- ── HLC timestamps audit ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hlc_events (
    id          BIGSERIAL PRIMARY KEY,
    node_id     TEXT        NOT NULL,
    hlc_l       BIGINT      NOT NULL,  -- physical component (ms)
    hlc_c       INT         NOT NULL,  -- logical counter
    op          TEXT        NOT NULL,  -- "tick" | "recv" | "snapshot"
    ref_id      TEXT,                  -- task_uuid, node_id, etc.
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_hlc_events_node ON hlc_events(node_id);
CREATE INDEX IF NOT EXISTS idx_hlc_events_ts   ON hlc_events(hlc_l DESC);

-- ── Write-Ahead Log entries ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wal_entries (
    id            BIGSERIAL PRIMARY KEY,
    wal_index     BIGINT      NOT NULL UNIQUE,
    term          INT         NOT NULL DEFAULT 0,
    op            TEXT        NOT NULL CHECK (op IN ('set','delete','snapshot')),
    key           TEXT        NOT NULL,
    value         JSONB,
    timestamp_ms  BIGINT      NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wal_entries_index ON wal_entries(wal_index);
CREATE INDEX IF NOT EXISTS idx_wal_entries_key   ON wal_entries(key);

-- ── Gossip membership ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS gossip_members (
    node_id      TEXT        PRIMARY KEY,
    address      TEXT        NOT NULL,
    state        TEXT        NOT NULL DEFAULT 'alive',
    incarnation  INT         NOT NULL DEFAULT 0,
    last_seen_ms BIGINT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── MVCC versions ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mvcc_versions (
    id         BIGSERIAL PRIMARY KEY,
    key        TEXT    NOT NULL,
    value      JSONB,
    hlc_l      BIGINT  NOT NULL,
    hlc_c      INT     NOT NULL,
    deleted    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mvcc_key_hlc ON mvcc_versions(key, hlc_l DESC, hlc_c DESC);

-- ── Distributed transactions (2PC) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS distributed_txns (
    txn_id       TEXT        PRIMARY KEY,
    state        TEXT        NOT NULL DEFAULT 'pending',
    mutations    JSONB       NOT NULL DEFAULT '[]',
    participants JSONB       NOT NULL DEFAULT '[]',
    votes        JSONB       NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_dtxns_state ON distributed_txns(state);

-- ── Dead Letter Queue ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dead_letter_queue (
    entry_id   TEXT        PRIMARY KEY,
    source     TEXT        NOT NULL,
    payload    JSONB,
    reason     TEXT        NOT NULL,
    attempts   INT         NOT NULL DEFAULT 1,
    resolved   BOOLEAN     NOT NULL DEFAULT FALSE,
    first_fail TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_fail  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dlq_source   ON dead_letter_queue(source);
CREATE INDEX IF NOT EXISTS idx_dlq_resolved ON dead_letter_queue(resolved);

-- ── Chaos experiment results ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chaos_results (
    id          BIGSERIAL   PRIMARY KEY,
    experiment  TEXT        NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL,
    ended_at    TIMESTAMPTZ NOT NULL,
    recovered   BOOLEAN     NOT NULL,
    verified    BOOLEAN,
    notes       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Anti-entropy sessions ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS anti_entropy_sessions (
    id           BIGSERIAL   PRIMARY KEY,
    node_id      TEXT        NOT NULL,
    peer_addr    TEXT        NOT NULL,
    keys_synced  INT         NOT NULL DEFAULT 0,
    error        TEXT,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Fencing token audit ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fencing_audit (
    id         BIGSERIAL   PRIMARY KEY,
    epoch      INT         NOT NULL,
    reason     TEXT,
    operator   TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Load balancer backend health ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lb_backends (
    node_id      TEXT        PRIMARY KEY,
    address      TEXT        NOT NULL,
    healthy      BOOLEAN     NOT NULL DEFAULT TRUE,
    weight       INT         NOT NULL DEFAULT 1,
    active_conns INT         NOT NULL DEFAULT 0,
    total_reqs   BIGINT      NOT NULL DEFAULT 0,
    errors       BIGINT      NOT NULL DEFAULT 0,
    p95_latency  FLOAT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Consistent hash ring snapshots ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ring_snapshots (
    id          BIGSERIAL   PRIMARY KEY,
    nodes       JSONB       NOT NULL,
    virtual_n   INT         NOT NULL DEFAULT 150,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── updated_at trigger for new tables ────────────────────────────────────────
DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOR tbl IN SELECT unnest(ARRAY[
        'hlc_events','wal_entries','gossip_members',
        'distributed_txns','dead_letter_queue',
        'chaos_results','lb_backends'
    ]) LOOP
        EXECUTE format(
            'CREATE TRIGGER trg_%I_updated_at
             BEFORE UPDATE ON %I
             FOR EACH ROW EXECUTE FUNCTION _set_updated_at()',
            tbl, tbl
        );
    END LOOP;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- ── Priority task queue persistence ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS priority_task_queue (
    id          BIGSERIAL   PRIMARY KEY,
    task_id     TEXT        NOT NULL UNIQUE,
    priority    INT         NOT NULL DEFAULT 1,
    run_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload     JSONB,
    claimed     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ptq_priority ON priority_task_queue(priority ASC, run_at ASC) WHERE NOT claimed;
