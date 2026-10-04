import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from client_package import prioritize, build_client_package

def test_prioritizes_critical_before_moderate():
    rows=prioritize([{"base_rule":"meta-viewport","impact":"moderate"},{"base_rule":"button-name","impact":"critical"}])
    assert rows[0]["base_rule"]=="button-name"

def test_client_package_contains_acceptance_path():
    p=build_client_package({"domain":"example.com","url":"https://example.com","findings":[{"base_rule":"button-name","impact":"critical"}]})
    assert p["product"]=="A11yForge"
    assert p["executive_summary"]["verified_findings"]==1
    assert "staging" in p["acceptance_plan"][0].lower()
