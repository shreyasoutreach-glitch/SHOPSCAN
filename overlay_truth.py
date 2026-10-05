"""Paired Overlay Truth Test.

Runs the same browser verification with detected overlay resources shipped and blocked.
Hashes only deterministic evidence fields so a repeated run with the same observations
produces the same per-finding evidence hash.
"""
import hashlib
import json
from overlay_signatures import detect_source_overlays
from rendered import CONFIRMED, ERROR

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,default=str)

def evidence_hash(finding, vendors, shipped_status, blocked_status):
    payload={
        "version":"1",
        "url":finding.get("url"),
        "rule":finding.get("base_rule") or finding.get("rule"),
        "signature":finding.get("signature"),
        "occurrence":finding.get("occurrence",0),
        "overlay_vendors":sorted(vendors),
        "shipped_status":shipped_status,
        "blocked_status":blocked_status,
        "selector":finding.get("path") or finding.get("selector"),
        "snippet":finding.get("snippet",""),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()

def run_overlay_truth_test(url, findings, source_overlays, verifier_factory):
    vendors=sorted({x.get("vendor") for x in source_overlays if x.get("vendor")})
    if not vendors:
        return {"status":"NOT_APPLICABLE","vendors":[],"findings":[],"deterministic":True}
    shipped_verifier=verifier_factory(())
    shipped=shipped_verifier.verify(url,findings)
    shipped_evidence=shipped_verifier.last_evidence
    blocked_verifier=verifier_factory(tuple(vendors))
    blocked=blocked_verifier.verify(url,findings)
    blocked_evidence=blocked_verifier.last_evidence
    rows=[]
    for f in findings:
        key=(f["signature"],f.get("occurrence",0))
        s=shipped.get(key,ERROR); b=blocked.get(key,ERROR)
        rows.append({
            "rule":f.get("base_rule") or f.get("rule"),
            "signature":f.get("signature"),
            "occurrence":f.get("occurrence",0),
            "shipped_status":s,
            "blocked_status":b,
            "remains_in_both":s==CONFIRMED and b==CONFIRMED,
            "evidence_hash":evidence_hash(f,vendors,s,b),
        })
    return {
        "status":"COMPLETE",
        "vendors":vendors,
        "blocked_resources":vendors,
        "findings":rows,
        "remaining_in_both":[x for x in rows if x["remains_in_both"]],
        "deterministic":True,
        "shipped_evidence":shipped_evidence,
        "blocked_evidence":blocked_evidence,
    }
