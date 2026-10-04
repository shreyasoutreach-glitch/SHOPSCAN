"""Tamper-evident assessment evidence ledger.

This creates deterministic hashes over the evidence actually captured by A11yForge.
It is tamper-evident, not a legal-admissibility determination.
"""
import hashlib
import json
from datetime import datetime, timezone

LEDGER_VERSION="1.0.0"

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,default=str)

def sha256(value):
    return hashlib.sha256(value.encode("utf-8","replace")).hexdigest()

def build_ledger(records, previous_hash=None):
    chain=[]
    prev=previous_hash or ""
    for index, record in enumerate(records):
        payload={"ledger_version":LEDGER_VERSION,"index":index,"previous_hash":prev,"record":record}
        digest=sha256(canonical(payload))
        entry={"index":index,"timestamp":datetime.now(timezone.utc).isoformat(),
               "previous_hash":prev,"record_hash":digest,"record":record}
        chain.append(entry)
        prev=digest
    return {"ledger_version":LEDGER_VERSION,"chain_length":len(chain),
            "head_hash":prev,"records":chain,"tamper_evident":True,
            "legal_status":"evidence_integrity aid, not a legal opinion"}

def assessment_ledger(result):
    records=[]
    evidence=result.get("rendered_evidence") or {}
    records.append({"type":"assessment","url":result.get("url"),"domain":result.get("domain"),
                    "scanner_version":result.get("scanner_version"),
                    "document_hash":result.get("document_hash"),
                    "assessment_status":result.get("assessment_status")})
    records.append({"type":"browser_evidence","evidence":evidence,
                    "overlay_evidence":result.get("overlay_evidence",{}),
                    "interaction_evidence":result.get("interaction_evidence",{})})
    records.append({"type":"findings","verified":[
        {"signature":f.get("signature"),"occurrence":f.get("occurrence"),
         "rule":f.get("rule"),"impact":f.get("impact"),"url":f.get("url")}
        for f in result.get("findings",[])
    ],"candidates":[
        {"signature":f.get("signature"),"occurrence":f.get("occurrence"),
         "rule":f.get("rule"),"impact":f.get("impact"),"url":f.get("url")}
        for f in result.get("candidate_findings",[])
    ]})
    return build_ledger(records)
