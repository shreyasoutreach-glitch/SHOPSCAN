"""Phase 5 regression and monitoring primitives.

This module compares evidence snapshots. It never interprets a change as legal compliance.
"""
import hashlib
import json
from datetime import datetime, timezone

def finding_key(f):
    return (
        f.get("signature") or f.get("base_rule") or f.get("rule") or "",
        int(f.get("occurrence",0)),
        f.get("source_page") or f.get("url") or "",
    )

def fingerprint(f):
    payload={
        "key":finding_key(f),
        "rule":f.get("rule") or f.get("base_rule"),
        "impact":f.get("impact"),
        "selector":f.get("path") or f.get("selector"),
        "snippet":f.get("snippet"),
    }
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def snapshot(result):
    findings=result.get("findings",[])
    return {
        "captured_at":datetime.now(timezone.utc).isoformat(),
        "finding_keys":sorted([finding_key(f) for f in findings]),
        "finding_fingerprints":sorted(fingerprint(f) for f in findings),
        "finding_count":len(findings),
        "rendered_status":result.get("rendered_status","UNKNOWN"),
        "scanner_version":result.get("scanner_version"),
        "evidence_head_hash":result.get("evidence_head_hash"),
    }

def diff(previous, current):
    prev={tuple(x) for x in (previous or {}).get("finding_keys",[])}
    curr={tuple(x) for x in (current or {}).get("finding_keys",[])}
    new=sorted(curr-prev)
    fixed=sorted(prev-curr)
    unchanged=sorted(prev&curr)
    if not previous:
        status="BASELINE"
    elif new:
        status="REGRESSED"
    elif fixed:
        status="IMPROVED"
    else:
        status="UNCHANGED"
    return {
        "status":status,
        "new":new,
        "fixed":fixed,
        "unchanged":unchanged,
        "new_count":len(new),
        "fixed_count":len(fixed),
        "unchanged_count":len(unchanged),
        "previous_fingerprint":hashlib.sha256(json.dumps(previous or {},sort_keys=True,separators=(",",":")).encode()).hexdigest(),
        "current_fingerprint":hashlib.sha256(json.dumps(current or {},sort_keys=True,separators=(",",":")).encode()).hexdigest(),
    }
