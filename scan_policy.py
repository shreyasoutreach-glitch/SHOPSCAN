"""Scan policy: authorization, opt-out and finding suppression."""
import os
from pathlib import Path
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parent
PUBLIC_PREVIEW=os.getenv("A11YFORGE_PUBLIC_PREVIEW","false").strip().lower() in {"1","true","yes","on"}

def _read(path):
    try:
        return [x.strip().lower() for x in Path(path).read_text().splitlines()
                if x.strip() and not x.lstrip().startswith("#")]
    except OSError:
        return []

def _domain(value):
    raw=value.strip().lower()
    if "://" in raw:
        return (urlsplit(raw).hostname or "").rstrip(".")
    return raw.split("/",1)[0].split(":",1)[0].rstrip(".")

def _matches(domain,entry):
    entry=_domain(entry)
    return bool(entry) and (domain==entry or domain.endswith("."+entry))

def blocked_domain(domain):
    domain=(domain or "").lower().rstrip(".")
    deny=_read(ROOT/"do_not_scan.txt")
    env=[x for x in os.getenv("A11YFORGE_DO_NOT_SCAN","").split(",") if x.strip()]
    suppressed=_read(ROOT/"suppress.txt")
    return any(_matches(domain,x) for x in [*deny,*env,*[x for x in suppressed if "@" not in x]])

def suppressed_rules(domain):
    rules=[]
    for entry in _read(ROOT/"suppress.txt"):
        if entry.startswith("rule:"):
            rules.append(entry[5:].strip())
    return rules

def apply_suppressions(domain,findings):
    rules=set(suppressed_rules(domain))
    if not rules:return findings
    return [f for f in findings if (f.get("base_rule") or f.get("rule")) not in rules]

def scan_scope(authorized):
    if authorized:
        return {"mode":"AUTHORIZED","max_pages":max(1,min(4,int(os.getenv("A11YFORGE_CRAWL_PAGES","4"))))}
    if PUBLIC_PREVIEW:
        return {"mode":"PUBLIC_PREVIEW","max_pages":1,
                "legal_review_required":True,
                "note":"Limited public preview is enabled. Legal review is required before relying on this mode."}
    return {"mode":"BLOCKED","max_pages":0}
