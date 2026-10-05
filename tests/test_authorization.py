import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from authorization import NOT_REQUESTED,REQUESTED,GRANTED,DECLINED,instructions,normalize_domain,issue_token
from scan_policy import scan_scope

def test_authorization_states_are_explicit():
    assert [NOT_REQUESTED,REQUESTED,GRANTED,DECLINED]==["NOT_REQUESTED","REQUESTED","GRANTED","DECLINED"]

def test_domain_normalization():
    assert normalize_domain("https://shop.example.com/path")=="shop.example.com"

def test_token_instructions_support_dns_and_meta():
    token=issue_token()
    i=instructions("shop.example.com",token)
    assert i["dns_name"].startswith("_a11yforge-verification.")
    assert token in i["meta_tag"]

def test_full_scope_requires_authorization(monkeypatch):
    monkeypatch.setattr("scan_policy.PUBLIC_PREVIEW",False)
    assert scan_scope(False)["mode"]=="BLOCKED"
    assert scan_scope(True)["mode"]=="AUTHORIZED"

def test_preview_is_one_page_and_marked_for_legal_review(monkeypatch):
    monkeypatch.setattr("scan_policy.PUBLIC_PREVIEW",True)
    s=scan_scope(False)
    assert s["mode"]=="PUBLIC_PREVIEW" and s["max_pages"]==1 and s["legal_review_required"] is True
