import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from monitoring import snapshot,diff

def _result(*rules):
    return {"findings":[{"rule":r,"signature":r+"|x","occurrence":0,"source_page":"https://fixture.test/"} for r in rules],
            "rendered_status":"OK","scanner_version":"1.6.0","evidence_head_hash":"abc"}

def test_monitoring_baseline():
    cur=snapshot(_result("button-name"))
    d=diff(None,cur)
    assert d["status"]=="BASELINE"
    assert d["new_count"]==1

def test_monitoring_detects_regression_and_fix():
    old=snapshot(_result("button-name","image-alt"))
    new=snapshot(_result("button-name","link-name"))
    d=diff(old,new)
    assert d["status"]=="REGRESSED"
    assert d["new_count"]==1
    assert d["fixed_count"]==1

def test_monitoring_unchanged():
    old=snapshot(_result("button-name"))
    new=snapshot(_result("button-name"))
    d=diff(old,new)
    assert d["status"]=="UNCHANGED"
    assert d["new_count"]==0 and d["fixed_count"]==0
