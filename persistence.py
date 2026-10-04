"""A11yForge persistence adapter.

Postgres is optional at runtime. The scanner remains stateless when DATABASE_URL is absent,
but monitoring/history features fail closed instead of silently pretending persistence exists.
"""
import json
import os
from datetime import datetime, timezone

try:
    import psycopg
except ImportError:
    psycopg = None

SCHEMA = """
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
"""

def configured():
    return bool(os.getenv("DATABASE_URL")) and psycopg is not None

def init_schema():
    if not configured():
        return False
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            for statement in SCHEMA.split(";"):
                statement=statement.strip()
                if statement:
                    cur.execute(statement)
        conn.commit()
    return True

def save_scan(scan_id, result):
    if not configured():
        return False
    created=datetime.now(timezone.utc)
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO scan_runs
                (id,created_at,domain,url,rendered_status,finding_count,candidate_count,result_json)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                ON CONFLICT (id) DO UPDATE SET result_json=EXCLUDED.result_json""",
                (scan_id,created,result.get("domain") or "",result.get("url") or "",
                 result.get("rendered_status") or "UNKNOWN",len(result.get("findings",[])),
                 len(result.get("candidate_findings",[])),json.dumps(result)),
            )
            for f in result.get("findings",[]):
                cur.execute(
                    """INSERT INTO finding_history
                    (scan_id,signature,occurrence,rule,impact,rendered_status,finding_json)
                    VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb)
                    ON CONFLICT DO NOTHING""",
                    (scan_id,f["signature"],int(f.get("occurrence",0)),f.get("rule"),
                     f.get("impact"),f.get("rendered_verification"),json.dumps(f)),
                )
        conn.commit()
    return True

def list_active_targets():
    if not configured():
        return []
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT id,url,cadence_minutes,last_run_at,last_status
                           FROM monitor_targets WHERE active=TRUE
                           ORDER BY id""")
            return [dict(zip(["id","url","cadence_minutes","last_run_at","last_status"],row))
                    for row in cur.fetchall()]
