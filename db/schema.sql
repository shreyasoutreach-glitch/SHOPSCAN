CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    domain TEXT NOT NULL,
    url TEXT NOT NULL,
    rendered_status TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    candidate_count INTEGER NOT NULL,
    result_json JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS monitor_targets (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    cadence_minutes INTEGER NOT NULL DEFAULT 1440,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scan_id TEXT,
    last_status TEXT,
    last_run_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS finding_history (
    id BIGSERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    signature TEXT NOT NULL,
    occurrence INTEGER NOT NULL,
    rule TEXT,
    impact TEXT,
    rendered_status TEXT,
    finding_json JSONB NOT NULL,
    UNIQUE(scan_id, signature, occurrence)
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_domain_created ON scan_runs(domain, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_history_signature ON finding_history(signature);
