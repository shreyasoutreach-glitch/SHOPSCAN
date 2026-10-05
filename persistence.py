"""A11yForge persistence adapter.

Postgres is optional at runtime. The scanner remains stateless when DATABASE_URL is absent,
but monitoring/history features fail closed instead of silently pretending persistence exists.
"""
import json
import logging
import os
from datetime import datetime, timezone

_AUTH_MEMORY = {}
LOGGER = logging.getLogger("a11yforge.scan")

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
CREATE TABLE IF NOT EXISTS domain_authorizations (
    domain TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    token_digest TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    declined_at TIMESTAMPTZ,
    verification_method TEXT
);
CREATE TABLE IF NOT EXISTS scan_requests (
    id TEXT PRIMARY KEY,
    requested_at TIMESTAMPTZ NOT NULL,
    domain TEXT NOT NULL,
    url TEXT NOT NULL,
    authorization_state TEXT NOT NULL,
    outcome TEXT NOT NULL,
    client_key TEXT,
    public_preview BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_scan_requests_domain_time ON scan_requests(domain, requested_at DESC);\nCREATE TABLE IF NOT EXISTS agency_workspaces (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    owner_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS agency_clients (
    id BIGSERIAL PRIMARY KEY,
    workspace_id BIGINT NOT NULL REFERENCES agency_workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    domain TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agency_clients_workspace ON agency_clients(workspace_id);
CREATE TABLE IF NOT EXISTS agency_share_links (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL REFERENCES agency_clients(id) ON DELETE CASCADE,
    token_digest TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS monitor_events (
    id BIGSERIAL PRIMARY KEY,
    target_id BIGINT NOT NULL REFERENCES monitor_targets(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    previous_snapshot JSONB NOT NULL,
    current_snapshot JSONB NOT NULL,
    diff_json JSONB NOT NULL
);
ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS workspace_id BIGINT;
ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS client_id BIGINT;
CREATE INDEX IF NOT EXISTS idx_monitor_events_target_time ON monitor_events(target_id,created_at DESC);
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

def save_authorization(domain,state,token_digest_value,verification_method=None):
    if not configured():
        _AUTH_MEMORY[domain]={"domain":domain,"state":state,"token_digest":token_digest_value,"verification_method":verification_method}
        return True
    now=datetime.now(timezone.utc)
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO domain_authorizations
                (domain,state,token_digest,requested_at,verified_at,declined_at,verification_method)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (domain) DO UPDATE SET state=EXCLUDED.state,
                token_digest=EXCLUDED.token_digest, verified_at=EXCLUDED.verified_at,
                declined_at=EXCLUDED.declined_at, verification_method=EXCLUDED.verification_method""",
                (domain,state,token_digest_value,now,now if state=="GRANTED" else None,
                 now if state=="DECLINED" else None,verification_method))
        conn.commit()
    return True

def get_authorization(domain):
    if not configured():
        return _AUTH_MEMORY.get(domain)
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT domain,state,token_digest,verification_method FROM domain_authorizations WHERE domain=%s",(domain,))
            row=cur.fetchone()
            return dict(zip(["domain","state","token_digest","verification_method"],row)) if row else None

def log_scan_request(request_id,domain,url,state,outcome,client_key,public_preview=False):
    LOGGER.info("scan_request id=%s domain=%s url=%s authorization_state=%s outcome=%s client=%s public_preview=%s",
                request_id,domain,url,state,outcome,client_key,public_preview)
    if not configured(): return True
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO scan_requests
                (id,requested_at,domain,url,authorization_state,outcome,client_key,public_preview)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (request_id,domain and datetime.now(timezone.utc),domain,url,state,outcome,client_key,public_preview))
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


def _rows(cur, sql, params=()):
    cur.execute(sql, params)
    cols=[d.name for d in cur.description] if cur.description else []
    return [dict(zip(cols,row)) for row in cur.fetchall()]

def create_workspace(name, owner_key):
    if not configured(): return None
    now=datetime.now(timezone.utc)
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO agency_workspaces(name,owner_key,created_at) VALUES (%s,%s,%s) RETURNING id",(name,owner_key,now))
            wid=cur.fetchone()[0]
        conn.commit()
    return wid

def list_workspaces(owner_key):
    if not configured(): return []
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            return _rows(cur,"SELECT id,name,created_at FROM agency_workspaces WHERE owner_key=%s ORDER BY id",(owner_key,))

def create_client(workspace_id,name,domain):
    if not configured(): return None
    now=datetime.now(timezone.utc)
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO agency_clients(workspace_id,name,domain,created_at) VALUES (%s,%s,%s,%s) RETURNING id",(workspace_id,name,domain,now))
            cid=cur.fetchone()[0]
        conn.commit()
    return cid

def list_clients(workspace_id):
    if not configured(): return []
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            return _rows(cur,"SELECT id,name,domain,created_at FROM agency_clients WHERE workspace_id=%s ORDER BY id",(workspace_id,))

def create_share_link(client_id,token_digest_value,expires_at):
    if not configured(): return None
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO agency_share_links(client_id,token_digest,expires_at,active) VALUES (%s,%s,%s,TRUE) RETURNING id",(client_id,token_digest_value,expires_at))
            sid=cur.fetchone()[0]
        conn.commit()
    return sid

def get_share_link(token_digest_value):
    if not configured(): return None
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            rows=_rows(cur,"SELECT id,client_id,expires_at,active FROM agency_share_links WHERE token_digest=%s",(token_digest_value,))
    if not rows: return None
    row=rows[0]
    if not row["active"] or row["expires_at"] <= datetime.now(timezone.utc):
        return None
    return row

def add_monitor_target(url,cadence_minutes=1440,workspace_id=None,client_id=None):
    if not configured(): return None
    cadence=max(60,min(int(cadence_minutes),10080))
    now=datetime.now(timezone.utc)
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO monitor_targets(url,active,cadence_minutes,created_at,workspace_id,client_id)
                           VALUES (%s,TRUE,%s,%s,%s,%s)
                           ON CONFLICT(url) DO UPDATE SET active=TRUE,cadence_minutes=EXCLUDED.cadence_minutes,
                           workspace_id=EXCLUDED.workspace_id,client_id=EXCLUDED.client_id
                           RETURNING id""",(url,cadence,now,workspace_id,client_id))
            tid=cur.fetchone()[0]
        conn.commit()
    return tid

def due_monitor_targets(limit=20):
    if not configured(): return []
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            return _rows(cur,"""SELECT id,url,cadence_minutes,last_run_at,last_status,last_scan_id,workspace_id,client_id
                               FROM monitor_targets
                               WHERE active=TRUE AND (last_run_at IS NULL OR last_run_at <= NOW() - (cadence_minutes * INTERVAL '1 minute'))
                               ORDER BY COALESCE(last_run_at,TO_TIMESTAMP(0)) LIMIT %s""",(max(1,min(int(limit),100)),))

def record_monitor_run(target_id,scan_id,status,previous_snapshot,current_snapshot,diff_json):
    if not configured(): return False
    now=datetime.now(timezone.utc)
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE monitor_targets SET last_scan_id=%s,last_status=%s,last_run_at=%s WHERE id=%s""",(scan_id,status,now,target_id))
            cur.execute("""INSERT INTO monitor_events(target_id,scan_id,created_at,status,previous_snapshot,current_snapshot,diff_json)
                           VALUES (%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb)""",
                        (target_id,scan_id,now,status,json.dumps(previous_snapshot or {}),json.dumps(current_snapshot or {}),json.dumps(diff_json or {})))
        conn.commit()
    return True

def latest_monitor_snapshot(target_id):
    if not configured(): return None
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            rows=_rows(cur,"SELECT current_snapshot FROM monitor_events WHERE target_id=%s ORDER BY created_at DESC LIMIT 1",(target_id,))
    return rows[0]["current_snapshot"] if rows else None

def list_monitor_events(target_id,limit=20):
    if not configured(): return []
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            return _rows(cur,"SELECT id,scan_id,created_at,status,diff_json FROM monitor_events WHERE target_id=%s ORDER BY created_at DESC LIMIT %s",(target_id,max(1,min(int(limit),100)),))
