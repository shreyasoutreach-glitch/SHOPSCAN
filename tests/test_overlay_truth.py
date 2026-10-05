import hashlib
from overlay_truth import evidence_hash, run_overlay_truth_test

class FakeVerifier:
    def __init__(self,blocked=()):
        self.blocked=blocked
        self.last_evidence={"status":"OK","blocked":list(blocked)}
    def verify(self,url,findings):
        return {(f["signature"],f.get("occurrence",0)):"CONFIRMED" for f in findings}

def test_evidence_hash_is_deterministic():
    f={"url":"http://fixture.test/","base_rule":"button-name","signature":"x","occurrence":0,"path":"button","snippet":"<button>"}
    assert evidence_hash(f,["UserWay"],"CONFIRMED","CONFIRMED")==evidence_hash(f,["UserWay"],"CONFIRMED","CONFIRMED")
    assert len(evidence_hash(f,["UserWay"],"CONFIRMED","CONFIRMED"))==64

def test_overlay_truth_requires_observed_vendor():
    f={"url":"http://fixture.test/","base_rule":"button-name","signature":"x","occurrence":0}
    r=run_overlay_truth_test("http://fixture.test/",[f],[],lambda blocked:FakeVerifier(blocked))
    assert r["status"]=="NOT_APPLICABLE"

def test_overlay_truth_records_findings_remaining_in_both_modes():
    f={"url":"http://fixture.test/","base_rule":"button-name","signature":"x","occurrence":0}
    r=run_overlay_truth_test("http://fixture.test/",[f],[{"vendor":"UserWay"}],lambda blocked:FakeVerifier(blocked))
    assert r["status"]=="COMPLETE"
    assert r["remaining_in_both"][0]["evidence_hash"]
