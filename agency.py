"""A11yForge agency workspace primitives.

Agency features are configuration/data-plane only. They do not grant scan authorization,
do not bypass consent, and never deploy merchant changes.
"""
import hashlib
import secrets
from datetime import datetime, timezone

def normalize_name(value: str) -> str:
    value=(value or "").strip()
    if not value or len(value)>160:
        raise ValueError("Workspace/client name is required and must be <=160 characters.")
    return value

def share_token() -> str:
    return "af_share_"+secrets.token_urlsafe(32)

def share_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def expiry_iso(days: int = 7) -> str:
    days=max(1,min(int(days),90))
    from datetime import timedelta
    return (datetime.now(timezone.utc)+timedelta(days=days)).isoformat()
