import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scan import analyze
from repair import repair_html

def test_duplicate_ids_are_detected():
    src="<html lang=\"en\"><head><title>Store</title></head><body><input id=\"email\"><input id=\"email\"></body></html>"
    r=analyze(src,"https://example.test/")
    assert any(x["base_rule"]=="duplicate-id" for x in r["findings"])

def test_missing_aria_reference_is_detected():
    src="<html lang=\"en\"><head><title>Store</title></head><body><button aria-labelledby=\"missing\">Save</button></body></html>"
    r=analyze(src,"https://example.test/")
    assert any(x["base_rule"]=="aria-reference" for x in r["findings"])

def test_aria_hidden_focusable_is_detected():
    src="<html lang=\"en\"><head><title>Store</title></head><body><div aria-hidden=\"true\"><button>Save</button></div></body></html>"
    r=analyze(src,"https://example.test/")
    assert any(x["base_rule"]=="aria-hidden-focusable" for x in r["findings"])

def test_empty_aria_label_has_safe_repair_when_visible_text_exists():
    src="<html lang=\"en\"><head><title>Store</title></head><body><button aria-label=\"\">Save</button></body></html>"
    r=analyze(src,"https://example.test/")
    f=next(x for x in r["findings"] if x["base_rule"]=="empty-aria-label")
    repaired=repair_html(src,[f])
    assert repaired["changed"] is True
    assert "aria-label=\"\"" not in repaired["html"]

def test_positive_tabindex_is_advisory_not_failure():
    src="<html lang=\"en\"><head><title>Store</title></head><body><a href=\"/x\" tabindex=\"5\">X</a></body></html>"
    r=analyze(src,"https://example.test/")
    assert any(x["rule"].startswith("advisory:positive-tabindex") for x in r["advisories"])