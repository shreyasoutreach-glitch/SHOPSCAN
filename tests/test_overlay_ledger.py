import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from overlay_signatures import detect_source_overlays
from evidence_ledger import build_ledger

def test_overlay_requires_observed_signature():
    r=detect_source_overlays(script_urls=["https://cdn.userway.org/widget.js"])
    assert any(x["vendor"]=="UserWay" for x in r)

def test_overlay_unknown_is_not_invented():
    r=detect_source_overlays(script_urls=["https://example.invalid/widget.js"])
    assert r == []

def test_evidence_ledger_is_hash_chained():
    r=build_ledger([{"type":"assessment","url":"https://example.com"}])
    assert r["tamper_evident"] is True
    assert len(r["head_hash"]) == 64
    assert r["records"][0]["previous_hash"] == ""
