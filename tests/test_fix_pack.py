import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pytest
from client_package import build_client_package,approve_package,export_json,export_html,export_pdf

def _package():
    return build_client_package({
        "domain":"fixture.test","url":"http://fixture.test/",
        "context":{"platform":"shopify"},
        "findings":[{
            "base_rule":"button-name","rule":"button-name","impact":"critical",
            "sc":["4.1.2"],"signature":"button-name|button|||","occurrence":0,
            "path":"html/body/button[1]","snippet":"<button></button>",
            "source_repairable":False,"evidence_hash":"a"*64
        }],
        "candidate_findings":[],"interaction_findings":[],"overlay_evidence":{}
    },{"repairs":[],"proposals":[],"regression":{"status":"NOT_RUN"}},"<html><body><button></button></body></html>")

def test_fix_pack_contains_required_developer_fields():
    p=_package()
    item=p["developer_fix_pack"][0]
    assert {"page","selector","wcag_criterion_reference","plain_english_explanation","dom_snippet","risk_level","patch","review_status"} <= set(item)

def test_exports_require_human_approval():
    p=_package()
    with pytest.raises(PermissionError): export_json(p)
    with pytest.raises(PermissionError): export_html(p)
    approved=approve_package(p,"reviewer@example.test")
    assert export_json(approved)
    assert export_html(approved)
    assert export_pdf(approved).startswith(b"%PDF")
    assert approved["report_disclaimer"]=="Evidence report, not legal advice or certification."

def test_ambiguous_patch_stays_review():
    p=_package()
    assert p["developer_fix_pack"][0]["review_status"]=="NEEDS HUMAN REVIEW"
